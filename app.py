import os
import json
import io
import datetime
import time
from functools import wraps
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Request, Form, File, UploadFile, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
import qrcode

# Initialize FastAPI App
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.environ.get("SECRET_KEY", "super_secure_secret_key"))

templates = Jinja2Templates(directory="templates")

# Cloudflare Environment Global (set during each fetch)
worker_env = None

# ============================
# CLOUDFLARE D1 ADAPTER (ASYNC)
# ============================

class D1Cursor:
    def __init__(self, db, query: str, params: List[Any] = None):
        self.db = db
        self.query = query
        self.params = params or []
        self._result = None

    async def _get_result(self):
        if self._result is None:
            # D1 prepare().bind().all() is async in Workers Python
            stmt = self.db.prepare(self.query).bind(*self.params)
            self._result = await stmt.all()
        return self._result

    async def fetchall(self) -> List[Dict[str, Any]]:
        res = await self._get_result()
        return [dict(row) for row in res.results]

    async def fetchone(self) -> Optional[Dict[str, Any]]:
        res = await self._get_result()
        if res.results and len(res.results) > 0:
            return dict(res.results[0])
        return None

class D1Connection:
    def __init__(self, db):
        self.db = db

    def execute(self, query: str, params: List[Any] = None):
        return D1Cursor(self.db, query, params)

    async def commit(self):
        # D1 commits automatically
        pass

    async def close(self):
        pass

def get_db():
    if worker_env is None or not hasattr(worker_env, 'DB'):
        # This shouldn't happen in production Workers
        raise Exception("Database binding 'DB' not found in environment")
    return D1Connection(worker_env.DB)

# Configuration
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
BASE_URL = os.environ.get("BASE_URL", "https://eventlogger.pages.dev")

def allowed_file(filename: str):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ============================
# FILTERS & UTILS
# ============================

def timestamp_format(value: str):
    try:
        dt = datetime.datetime.fromisoformat(value)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return value

templates.env.filters["timestamp_format"] = timestamp_format

# Base URL for QR codes and event links (set in environment for production)
# Example: BASE_URL=https://eventlogger-g6c5.onrender.com
BASE_URL = os.environ.get("BASE_URL", None)

# Global Queue for logs
log_queue = queue.Queue()

# ============================
# DATABASE HELPER
# ============================

def get_db_connection():
    conn = sqlite3.connect("event.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            role TEXT,
            name TEXT,
            phone TEXT,
            address TEXT,
            profile_pic TEXT,
            approved INTEGER DEFAULT 0
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_name TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS event_fields (
            field_id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER,
            field_label TEXT,
            field_type TEXT,
            is_required INTEGER,
            field_order INTEGER
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS event_admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER,
            admin_username TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER,
            data TEXT,
            timestamp TEXT
        )
    """)
    
    # Check if superadmin exists, if not create one
    superadmin = c.execute("SELECT * FROM users WHERE role='superadmin'").fetchone()
    if not superadmin:
        # Default Superadmin: admin/admin
        c.execute("INSERT INTO users (username, password, role, name, phone, address, approved) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  ('admin', 'admin', 'superadmin', 'Super Admin', '000-000-0000', 'Server Room', 1))
        print("Created default superadmin: admin/admin")

    conn.commit()
    conn.close()

# ============================
# CONTEXT HELPERS
# ============================

async def get_current_user(request: Request):
    username = request.session.get('username')
    if username:
        conn = get_db()
        user = await conn.execute("SELECT * FROM users WHERE username = ?", [username]).fetchone()
        if user:
            return dict(user)
    return None

# Access control decorators (FastAPI style)
async def login_required(request: Request):
    if 'username' not in request.session:
        # FastAPI doesn't have RedirectResponse in Depends easily with Flash,
        # but we can raise an exception or handle it.
        raise HTTPException(status_code=303, detail="Login required", headers={"Location": "/login"})
    return request.session['username']

async def superadmin_required(request: Request):
    if request.session.get('role') != 'superadmin':
        raise HTTPException(status_code=303, detail="Superadmin only", headers={"Location": "/login"})
    return request.session['username']

# ============================
# ROUTES
# ============================

@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    user = await get_current_user(request)
    return templates.TemplateResponse("login.html", {"request": request, "user": user})

@app.post("/")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    conn = get_db()
    user = await conn.execute("SELECT * FROM users WHERE username = ?", [username]).fetchone()
    
    if user and user['password'] == password: # In prod use hash!
        if user['approved'] == 0:
            return templates.TemplateResponse("pending.html", {"request": request, "user": None})
        
        request.session['username'] = user['username']
        request.session['role'] = user['role']
        request.session['name'] = user['name']
        
        if user['role'] == 'superadmin':
            return RedirectResponse(url="/superadmin", status_code=303)
        else:
            return RedirectResponse(url="/staff/events", status_code=303)
    else:
        # Simple error handling for now as FastAPI doesn't have Flask-style flash messages by default
        return templates.TemplateResponse("login.html", {"request": request, "user": None, "error": "Invalid credentials"})

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    user = await get_current_user(request)
    return templates.TemplateResponse("register.html", {"request": request, "user": user})

@app.post("/register")
async def register(request: Request, 
                   username: str = Form(...), 
                   password: str = Form(...), 
                   name: str = Form(...), 
                   phone: str = Form(...), 
                   address: str = Form(...)):
    conn = get_db()
    existing = await conn.execute("SELECT 1 FROM users WHERE username = ?", [username]).fetchone()
    if existing:
        return templates.TemplateResponse("register.html", {"request": request, "user": None, "error": "Username taken"})
    
    try:
        await conn.execute("INSERT INTO users (username, password, role, name, phone, address, approved) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     [username, password, 'staff', name, phone, address, 0])
        return RedirectResponse(url="/", status_code=303)
    except Exception as e:
        return templates.TemplateResponse("register.html", {"request": request, "user": None, "error": str(e)})

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/", status_code=303)

# --- SUPERADMIN ROUTES ---

@app.route('/superadmin')
@login_required
@superadmin_required
def superadmin_dashboard():
    conn = get_db_connection()
    
    # Fetch pending staff
    pending_staff = conn.execute("SELECT * FROM users WHERE role != 'superadmin' AND approved = 0").fetchall()
    
    # Fetch approved staff
    approved_staff = conn.execute("SELECT * FROM users WHERE role != 'superadmin' AND approved = 1").fetchall()
    
    # Fetch all events with staff count
    all_events = conn.execute("""
        SELECT e.*, COUNT(ea.id) as staff_count 
        FROM events e 
        LEFT JOIN event_admins ea ON e.event_id = ea.event_id 
        GROUP BY e.event_id
    """).fetchall()
    
    conn.close()
    return render_template('superadmin/dashboard.html', 
                           pending_staff=pending_staff, 
                           approved_staff=approved_staff, 
                           all_events=all_events)

@app.route('/superadmin/event/create', methods=['POST'])
@login_required
@superadmin_required
def superadmin_create_event():
    event_name = request.form['event_name']
    conn = get_db_connection()
    conn.execute("INSERT INTO events (event_name) VALUES (?)", (event_name,))
    conn.commit()
    conn.close()
    flash(f"Event '{event_name}' created.", "success")
    return redirect(url_for('superadmin_dashboard'))

@app.route('/superadmin/approve/<username>', methods=['POST'])
@login_required
@superadmin_required
def superadmin_approve_staff(username):
    conn = get_db_connection()
    conn.execute("UPDATE users SET approved = 1 WHERE username = ?", (username,))
    conn.commit()
@app.get("/superadmin", response_class=HTMLResponse)
async def superadmin_dashboard(request: Request, _ = Depends(superadmin_required)):
    conn = get_db()
    pending_staff = await conn.execute("SELECT * FROM users WHERE role = 'staff' AND approved = 0").fetchall()
    approved_staff = await conn.execute("SELECT * FROM users WHERE role = 'staff' AND approved = 1").fetchall()
    events = await conn.execute("SELECT * FROM events").fetchall()
    
    user = await get_current_user(request)
    return templates.TemplateResponse("superadmin/dashboard.html", {
        "request": request,
        "user": user,
        "pending_staff": pending_staff,
        "approved_staff": approved_staff,
        "events": events
    })

@app.get("/superadmin/approve/{username}")
async def approve_user(username: str, _ = Depends(superadmin_required)):
    conn = get_db()
    await conn.execute("UPDATE users SET approved = 1 WHERE username = ?", [username])
    return RedirectResponse(url="/superadmin", status_code=303)

@app.get("/superadmin/reject/{username}")
async def reject_user(username: str, _ = Depends(superadmin_required)):
    conn = get_db()
    await conn.execute("DELETE FROM users WHERE username = ?", [username])
    return RedirectResponse(url="/superadmin", status_code=303)

@app.get("/superadmin/manage_staff/{event_id}", response_class=HTMLResponse)
async def manage_staff(request: Request, event_id: int, _ = Depends(superadmin_required)):
    conn = get_db()
    event = await conn.execute("SELECT * FROM events WHERE event_id = ?", [event_id]).fetchone()
    
    assigned_staff = await conn.execute("""
        SELECT u.username, u.name 
        FROM users u 
        JOIN event_admins ea ON u.username = ea.admin_username 
        WHERE ea.event_id = ?
    """, [event_id]).fetchall()
    
    unassigned_staff = await conn.execute("""
        SELECT username, name FROM users 
        WHERE role = 'staff' AND approved = 1 
        AND username NOT IN (SELECT admin_username FROM event_admins WHERE event_id = ?)
    """, [event_id]).fetchall()
    
    user = await get_current_user(request)
    return templates.TemplateResponse("superadmin/manage_staff.html", {
        "request": request,
        "user": user,
        "event": event,
        "assigned_staff": assigned_staff,
        "unassigned_staff": unassigned_staff
    })

@app.post("/superadmin/assign_staff")
async def assign_staff(event_id: int = Form(...), username: str = Form(...), _ = Depends(superadmin_required)):
    conn = get_db()
    await conn.execute("INSERT INTO event_admins (event_id, admin_username) VALUES (?, ?)", [event_id, username])
    return RedirectResponse(url=f"/superadmin/manage_staff/{event_id}", status_code=303)

@app.get("/superadmin/unassign_staff/{event_id}/{username}")
async def unassign_staff(event_id: int, username: str, _ = Depends(superadmin_required)):
    conn = get_db()
    await conn.execute("DELETE FROM event_admins WHERE event_id = ? AND admin_username = ?", [event_id, username])
    return RedirectResponse(url=f"/superadmin/manage_staff/{event_id}", status_code=303)

@app.route('/superadmin/event/delete/<int:event_id>', methods=['POST'])
@app.post("/superadmin/event/add")
async def add_event(event_name: str = Form(...), _ = Depends(superadmin_required)):
    conn = get_db()
    await conn.execute("INSERT INTO events (event_name) VALUES (?)", [event_name])
    return RedirectResponse(url="/superadmin", status_code=303)

@app.get("/superadmin/event/edit/{event_id}", response_class=HTMLResponse)
async def edit_event_page(request: Request, event_id: int, _ = Depends(superadmin_required)):
    conn = get_db()
    event = await conn.execute("SELECT * FROM events WHERE event_id = ?", [event_id]).fetchone()
    fields = await conn.execute("SELECT * FROM event_fields WHERE event_id = ? ORDER BY field_order", [event_id]).fetchall()
    
    user = await get_current_user(request)
    return templates.TemplateResponse("superadmin/edit_form.html", {
        "request": request,
        "user": user,
        "event": event,
        "fields": fields
    })

@app.post("/superadmin/event/update_fields/{event_id}")
async def update_event_fields(request: Request, event_id: int, _ = Depends(superadmin_required)):
    form_data = await request.form()
    conn = get_db()
    
    # Simple strategy: delete and recreate fields for this event
    await conn.execute("DELETE FROM event_fields WHERE event_id = ?", [event_id])
    
    labels = form_data.getlist('field_label[]')
    types = form_data.getlist('field_type[]')
    requireds = form_data.getlist('is_required[]')
    
    for i in range(len(labels)):
        if labels[i].strip():
            await conn.execute("""
                INSERT INTO event_fields (event_id, field_label, field_type, is_required, field_order)
                VALUES (?, ?, ?, ?, ?)
            """, [event_id, labels[i], types[i], 1 if str(requireds[i]) == '1' else 0, i])
            
    return RedirectResponse(url=f"/superadmin/event/edit/{event_id}", status_code=303)

@app.post("/superadmin/event/delete/{event_id}")
async def delete_event(event_id: int, _ = Depends(superadmin_required)):
    conn = get_db()
    await conn.execute("DELETE FROM events WHERE event_id = ?", [event_id])
    await conn.execute("DELETE FROM event_fields WHERE event_id = ?", [event_id])
    await conn.execute("DELETE FROM event_admins WHERE event_id = ?", [event_id])
    return RedirectResponse(url="/superadmin", status_code=303)

@app.route('/superadmin/field/delete/<int:field_id>', methods=['POST'])
@login_required
@superadmin_required
def superadmin_delete_field(field_id):
    conn = get_db_connection()
    field = conn.execute("SELECT event_id FROM event_fields WHERE field_id = ?", (field_id,)).fetchone()
    if field:
        conn.execute("DELETE FROM event_fields WHERE field_id = ?", (field_id,)).fetchone()
        conn.commit()
        flash("Field deleted.", "success")
        conn.close()
        return redirect(url_for('superadmin_edit_event_form', event_id=field['event_id']))
    conn.close()
    return redirect(url_for('superadmin_dashboard'))

@app.route('/superadmin/profile')
@login_required
@superadmin_required
def superadmin_profile():
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (session['username'],)).fetchone()
    conn.close()
    return render_template('superadmin/profile.html', user=user)

@app.route('/superadmin/update', methods=['POST'])
@login_required
@superadmin_required
def superadmin_update_profile():
    password = request.form.get('password')
    file = request.files.get('profile_pic')
    pic_filename = None
    
    if file and allowed_file(file.filename):
        filename = werkzeug.utils.secure_filename(file.filename)
        filename = f"{session['username']}_{int(time.time())}_{filename}"
        
        # Save to R2 instead of local folder
        if worker_env and hasattr(worker_env, 'BUCKET'):
            file_data = file.read()
            worker_env.BUCKET.put(filename, file_data)
        else:
            # Local fallback for dev
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        pic_filename = filename
        
    conn = get_db_connection()
    if password:
        conn.execute("UPDATE users SET password = ? WHERE username = ?", (password, session['username']))
    
    if pic_filename:
        conn.execute("UPDATE users SET profile_pic = ? WHERE username = ?", (pic_filename, session['username']))
        
    conn.commit()
    conn.close()
    flash("Profile updated.", "success")
    return redirect(url_for('superadmin_profile'))


# --- STAFF ROUTES ---

@app.route('/staff/events')
@login_required
def staff_events():
    conn = get_db_connection()
    # If superadmin, show everything? Or redirect? Original code had different dashboards.
    # If staff calls this, they see their assigned events.
    if session['role'] != 'staff':
        # Superadmin can view too?
        pass # Allow them to see "My Events" (which might be none unless they assign themselves)
        
    events = conn.execute("""
        SELECT e.* 
        FROM events e 
        JOIN event_admins ea ON e.event_id = ea.event_id 
        WHERE ea.admin_username = ?
    """, (session['username'],)).fetchall()
        ld = dict(l)
        try:
            ld['data'] = json.loads(ld['data'])
        except:
            ld['data'] = {}
        logs.append(ld)
        
    count = len(logs) # Actually current processed count should be total count
    # Let's get total count
    conn = get_db_connection()
    total_count = conn.execute("SELECT COUNT(*) FROM logs WHERE event_id = ?", (event_id,)).fetchone()[0]
    conn.close()
    
    return render_template('staff/logs.html', event=event, fields=fields, logs=logs, log_count=total_count)

@app.route('/staff/log/delete/<int:log_id>/<int:event_id>', methods=['POST'])
@login_required
def delete_log(log_id, event_id):
    # Check access
    if session['role'] != 'superadmin':
        conn = get_db_connection()
        access = conn.execute("SELECT 1 FROM event_admins WHERE event_id = ? AND admin_username = ?", 
                              (event_id, session['username'])).fetchone()
        conn.close()
        if not access:
            flash("Access denied.", "error")
            return redirect(url_for('staff_events'))
            
    conn = get_db_connection()
    conn.execute("DELETE FROM logs WHERE log_id = ?", (log_id,))
    conn.commit()
    conn.close()
    flash("Log entry deleted.", "success")
    return redirect(url_for('view_logs', event_id=event_id))

# --- PUBLIC / API ---

@app.route('/attend/<int:event_id>', methods=['GET', 'POST'])
def attend_event(event_id):
    conn = get_db_connection()
    event = conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
    if not event:
        conn.close()
        return "Event not found", 404
        
    fields = conn.execute("SELECT * FROM event_fields WHERE event_id = ? ORDER BY field_order ASC", (event_id,)).fetchall()
    
    if request.method == 'POST':
        data = {}
        for field in fields:
            label = field['field_label']
            value = request.form.get(label)
            data[label] = value
        
        # Get current timestamp
        current_time = datetime.datetime.now()
        
        # Cloudflare Direct Write (instead of queue)
        conn.execute(
            "INSERT INTO logs (event_id, data, timestamp) VALUES (?, ?, ?)",
            (event_id, json.dumps(data), current_time.isoformat())
        )
        conn.commit()
        conn.close()
        
        # Redirect to success page with formatted timestamp
        formatted_time = current_time.strftime('%B %d, %Y at %I:%M:%S %p')
        return render_template('attend_success.html', event=event, timestamp=formatted_time)
        
    conn.close()
    return render_template('attend.html', event=event, fields=fields)

@app.route('/qr_code/<int:event_id>')
def qr_code_route(event_id):
    # Use BASE_URL if set, otherwise fall back to request.host_url
    host_url = BASE_URL if BASE_URL else request.host_url.rstrip('/')
    url = f"{host_url}/attend/{event_id}"
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_byte_arr.seek(0)
    
    return StreamingResponse(img_byte_arr, media_type="image/png")

@app.get("/api/event/{event_id}/logs")
@login_required
def api_event_logs(event_id):
    since_id = request.args.get('since', 0, type=int)
    
    conn = get_db_connection()
    logs_raw = conn.execute("SELECT * FROM logs WHERE event_id = ? AND log_id > ? ORDER BY log_id DESC", (event_id, since_id)).fetchall()
    conn.close()
    
    logs = []
    for l in logs_raw:
        ld = dict(l)
        try:
            ld['data'] = json.loads(ld['data'])
        except:
            ld['data'] = {}
        # Pre-format timestamp for JS
        try:
             dt = datetime.datetime.fromisoformat(ld['timestamp'])
             ld['formatted_timestamp'] = dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
             ld['formatted_timestamp'] = ld['timestamp']
        logs.append(ld)
        
    return jsonify({'logs': logs})

@app.get("/uploads/{filename}")
async def uploaded_file(filename: str):
    try:
        # Fetch from R2
        object = await worker_env.BUCKET.get(filename)
        if object is None:
            raise HTTPException(status_code=404, detail="File not found")
        
        # Stream the object back
        # The object has a 'body' which is a stream-like object in Pyodide
        return StreamingResponse(io.BytesIO(await object.arrayBuffer()), media_type="image/jpeg")
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.route('/queue_status')
@login_required
def queue_status():
    # Queue is removed in Workers, return 0
    return jsonify({'size': 0})

# ============================
# CLOUDFLARE WORKER ENTRY POINT
# ============================

class Default:
    def __init__(self, env):
        global worker_env
        worker_env = env

    async def fetch(self, request, env):
        global worker_env
        worker_env = env
        # FastAPI is natively ASGI, so we just call the app
        return await app(request, env)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5002))
    app.run(debug=True, host='0.0.0.0', port=port)
