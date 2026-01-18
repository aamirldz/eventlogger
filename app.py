
import os
import sqlite3
import json
import io
import queue
import threading
import time
import socket
import datetime
from functools import wraps

import flask
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file, send_from_directory
import werkzeug.utils

# QR Code generation
import qrcode

# Initialize Flask App
app = Flask(__name__)
app.secret_key = "super_secure_secret_key"  # Change this for production!

# Configuration
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

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
# UTILS & FILTERS
# ============================

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.template_filter('timestamp_format')
def timestamp_format(value):
    try:
        # Assuming ISO format string
        dt = datetime.datetime.fromisoformat(value)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return value

def get_ip_address():
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        return ip
    except:
        return "127.0.0.1"

# ============================
# CONTEXT PROCESSOR
# ============================

@app.context_processor
def inject_user():
    """Inject current user into all templates for header component."""
    user = None
    if 'username' in session:
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (session['username'],)).fetchone()
        conn.close()
        if user:
            user = dict(user)
    return dict(user=user)

# ============================
# BACKGROUND WORKER
# ============================

def log_consumer():
    print("CONSUMER THREAD: Running...")
    while True:
        try:
            log_data = log_queue.get()
            if not log_data:
                continue

            conn = get_db_connection()
            conn.execute(
                "INSERT INTO logs (event_id, data, timestamp) VALUES (?, ?, ?)",
                (
                    log_data["event_id"],
                    json.dumps(log_data["data"]),
                    log_data["timestamp"],
                ),
            )
            conn.commit()
            conn.close()
            # print(f"CONSUMER: Saved log for event {log_data['event_id']}")
        except Exception as e:
            print("CONSUMER ERROR:", e)
        time.sleep(0.1)

# ============================
# AUTH DECORATORS
# ============================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Please login first.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'superadmin':
            flash("Access denied. Superadmin only.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ============================
# ROUTES
# ============================

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        
        if user and user['password'] == password: # In prod use hash!
            if user['approved'] == 0:
                return render_template('pending.html')
            
            session['username'] = user['username']
            session['role'] = user['role']
            session['name'] = user['name']
            
            if user['role'] == 'superadmin':
                return redirect(url_for('superadmin_dashboard'))
            else:
                return redirect(url_for('staff_events'))
        else:
            flash("Invalid credentials.", "error")
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        name = request.form['name']
        phone = request.form['phone']
        address = request.form['address']
        
        conn = get_db_connection()
        existing = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            flash("Username already taken.", "error")
            conn.close()
            return render_template('register.html')
        
        try:
            conn.execute("INSERT INTO users (username, password, role, name, phone, address, approved) VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (username, password, 'staff', name, phone, address, 0)) # Default role is staff, pending approval
            conn.commit()
            flash("Registration successful! Please wait for approval.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"Error: {e}", "error")
        finally:
            conn.close()
            
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

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
    conn.close()
    flash(f"Staff '{username}' approved.", "success")
    return redirect(url_for('superadmin_dashboard'))

@app.route('/superadmin/delete/<username>', methods=['POST'])
@login_required
@superadmin_required
def superadmin_delete_staff(username):
    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.execute("DELETE FROM event_admins WHERE admin_username = ?", (username,)) # Cleanup assignments
    conn.commit()
    conn.close()
    flash(f"Staff '{username}' deleted/rejected.", "success")
    return redirect(url_for('superadmin_dashboard'))

@app.route('/superadmin/event/delete/<int:event_id>', methods=['POST'])
@login_required
@superadmin_required
def superadmin_delete_event(event_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM events WHERE event_id = ?", (event_id,))
    conn.execute("DELETE FROM event_fields WHERE event_id = ?", (event_id,))
    conn.execute("DELETE FROM event_admins WHERE event_id = ?", (event_id,))
    conn.execute("DELETE FROM logs WHERE event_id = ?", (event_id,))
    conn.commit()
    conn.close()
    flash("Event deleted.", "success")
    return redirect(url_for('superadmin_dashboard'))

@app.route('/superadmin/event/staff/<int:event_id>')
@login_required
@superadmin_required
def superadmin_manage_event_staff(event_id):
    conn = get_db_connection()
    event = conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
    if not event:
        conn.close()
        flash("Event not found", "error")
        return redirect(url_for('superadmin_dashboard'))
        
    # Get assigned staff
    assigned_staff = conn.execute("""
        SELECT u.* FROM users u 
        JOIN event_admins ea ON u.username = ea.admin_username 
        WHERE ea.event_id = ?
    """, (event_id,)).fetchall()
    
    # Get available staff (all staff - assigned)
    unassigned_staff = conn.execute("""
        SELECT * FROM users 
        WHERE role != 'superadmin' AND approved = 1 
        AND username NOT IN (SELECT admin_username FROM event_admins WHERE event_id = ?)
    """, (event_id,)).fetchall()
    
    conn.close()
    return render_template('superadmin/manage_staff.html', event=event, assigned_staff=assigned_staff, unassigned_staff=unassigned_staff)

@app.route('/superadmin/event/staff/add/<int:event_id>/<username>', methods=['POST'])
@login_required
@superadmin_required
def superadmin_add_event_staff(event_id, username):
    conn = get_db_connection()
    conn.execute("INSERT INTO event_admins (event_id, admin_username) VALUES (?, ?)", (event_id, username))
    conn.commit()
    conn.close()
    flash(f"Assigned {username} to event.", "success")
    return redirect(url_for('superadmin_manage_event_staff', event_id=event_id))

@app.route('/superadmin/event/staff/remove/<int:event_id>/<username>', methods=['POST'])
@login_required
@superadmin_required
def superadmin_remove_event_staff(event_id, username):
    conn = get_db_connection()
    conn.execute("DELETE FROM event_admins WHERE event_id = ? AND admin_username = ?", (event_id, username))
    conn.commit()
    conn.close()
    flash(f"Removed {username} from event.", "success")
    return redirect(url_for('superadmin_manage_event_staff', event_id=event_id))

@app.route('/superadmin/event/edit/<int:event_id>', methods=['GET', 'POST'])
@login_required
@superadmin_required
def superadmin_edit_event_form(event_id):
    conn = get_db_connection()
    event = conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
    
    if request.method == 'POST':
        field_label = request.form['field_label']
        field_type = request.form['field_type']
        is_required = 1 if 'is_required' in request.form else 0
        
        conn.execute("INSERT INTO event_fields (event_id, field_label, field_type, is_required) VALUES (?, ?, ?, ?)",
                     (event_id, field_label, field_type, is_required))
        conn.commit()
        flash("Field added.", "success")
        
    fields = conn.execute("SELECT * FROM event_fields WHERE event_id = ?", (event_id,)).fetchall()
    conn.close()
    return render_template('superadmin/edit_form.html', event=event, fields=fields)

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
    name = request.form.get('name') # Wait, superadmin template doesnt edit name/phone/address in my new template?
    # Ah, I copied the original superadmin profile template which ONLY had username/password/pic.
    # The ADMIN profile had all fields.
    # Let's check original template again.
    # Lines 724+: ONLY username, password, profile_pic.
    # Okay.
    
    password = request.form.get('password')
    
    file = request.files.get('profile_pic')
    pic_filename = None
    
    if file and allowed_file(file.filename):
        filename = werkzeug.utils.secure_filename(file.filename)
        # Unique func
        filename = f"{session['username']}_{int(time.time())}_{filename}"
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
    
    # Process for URL display
    # We need to construct the full URL for the attendee form
    events_list = []
    # Use BASE_URL if set, otherwise fall back to request.host_url
    host_url = BASE_URL if BASE_URL else request.host_url.rstrip('/')
    for e in events:
        evt = dict(e)
        evt['url'] = f"{host_url}/attend/{e['event_id']}"
        events_list.append(evt)
        
    conn.close()
    return render_template('staff/events.html', events=events_list)

@app.route('/staff/profile')
@login_required
def staff_profile():
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (session['username'],)).fetchone()
    conn.close()
    return render_template('staff/profile.html', user=user)

@app.route('/staff/update', methods=['POST'])
@login_required
def staff_update_profile():
    name = request.form['name']
    phone = request.form['phone']
    address = request.form['address']
    password = request.form.get('password')
    
    file = request.files.get('profile_pic')
    pic_filename = None
     
    if file and allowed_file(file.filename):
        filename = werkzeug.utils.secure_filename(file.filename)
        filename = f"{session['username']}_{int(time.time())}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        pic_filename = filename
        
    conn = get_db_connection()
    query = "UPDATE users SET name=?, phone=?, address=?"
    params = [name, phone, address]
    
    if password:
        query += ", password=?"
        params.append(password)
        
    if pic_filename:
        query += ", profile_pic=?"
        params.append(pic_filename)
        
    query += " WHERE username=?"
    params.append(session['username'])
    
    conn.execute(query, tuple(params))
    conn.commit()
    conn.close()
    flash("Profile updated.", "success")
    return redirect(url_for('staff_profile'))
    
@app.route('/staff/event/<int:event_id>/logs')
@login_required
def view_logs(event_id):
    # Check access
    if session['role'] != 'superadmin':
        conn = get_db_connection()
        access = conn.execute("SELECT 1 FROM event_admins WHERE event_id = ? AND admin_username = ?", 
                              (event_id, session['username'])).fetchone()
        conn.close()
        if not access:
            flash("You do not have access to this event.", "error")
            return redirect(url_for('staff_events'))

    conn = get_db_connection()
    event = conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
    fields = conn.execute("SELECT * FROM event_fields WHERE event_id = ? ORDER BY field_order ASC", (event_id,)).fetchall()
    
    # Get initial logs (limit 50?)
    logs_raw = conn.execute("SELECT * FROM logs WHERE event_id = ? ORDER BY log_id DESC LIMIT 50", (event_id,)).fetchall()
    conn.close()
    
    # Process logs (data is JSON)
    logs = []
    for l in logs_raw:
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
        
        # Add to queue
        log_entry = {
            "event_id": event_id,
            "data": data,
            "timestamp": datetime.datetime.now().isoformat()
        }
        log_queue.put(log_entry)
        
        # We can also render a success page
        # For now, just render same page with success message?
        # Or redirect to self with success?
        # Let's flash and redirect
        # Note: attend.html doesn't have checks for flash messages in my previous extraction?
        # Layout HAS flash messages! So it's fine.
        flash("Attendance logged successfully!", "success")
        conn.close()
        return redirect(url_for('attend_event', event_id=event_id))
        
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
    
    byte_io = io.BytesIO()
    img.save(byte_io, 'PNG')
    byte_io.seek(0)
    return send_file(byte_io, mimetype='image/png')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/event/<int:event_id>/logs')
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

@app.route('/queue_status')
@login_required
def queue_status():
    return jsonify({'size': log_queue.qsize()})

# Initialize logic unconditionally (for Gunicorn workers)
init_db()

# Start consumer thread
# Daemon threads are killed when the main process exits
ct = threading.Thread(target=log_consumer, daemon=True)
ct.start()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5002))
    # Disable debug in production (or rely on env vars)
    app.run(debug=True, host='0.0.0.0', port=port)
