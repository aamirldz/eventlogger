import { Hono } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';

const app = new Hono();

// ============================
// SIMPLE TEMPLATE ENGINE
// ============================

// Read template files - they're imported as text modules
import layoutHtml from '../templates/layout.html';
import loginHtml from '../templates/login.html';
import registerHtml from '../templates/register.html';
import pendingHtml from '../templates/pending.html';
import attendHtml from '../templates/attend.html';
import attendSuccessHtml from '../templates/attend_success.html';
import staffEventsHtml from '../templates/staff/events.html';
import staffLogsHtml from '../templates/staff/logs.html';
import staffProfileHtml from '../templates/staff/profile.html';
import superadminDashboardHtml from '../templates/superadmin/dashboard.html';
import superadminEditFormHtml from '../templates/superadmin/edit_form.html';
import superadminManageStaffHtml from '../templates/superadmin/manage_staff.html';
import superadminProfileHtml from '../templates/superadmin/profile.html';
import robotHtml from '../templates/components/robot.html';
import userHeaderHtml from '../templates/components/user_header.html';

const TEMPLATES = {
    'layout': layoutHtml,
    'login': loginHtml,
    'register': registerHtml,
    'pending': pendingHtml,
    'attend': attendHtml,
    'attend_success': attendSuccessHtml,
    'staff/events': staffEventsHtml,
    'staff/logs': staffLogsHtml,
    'staff/profile': staffProfileHtml,
    'superadmin/dashboard': superadminDashboardHtml,
    'superadmin/edit_form': superadminEditFormHtml,
    'superadmin/manage_staff': superadminManageStaffHtml,
    'superadmin/profile': superadminProfileHtml,
    'components/robot': robotHtml,
    'components/user_header': userHeaderHtml,
};

function render(templateName, context = {}) {
    let template = TEMPLATES[templateName] || '';

    // Handle {% extends 'layout.html' %}
    const extendsMatch = template.match(/\{%\s*extends\s*['"]([^'"]+)['"]\s*%\}/);
    if (extendsMatch) {
        const parentName = extendsMatch[1].replace('.html', '').replace('/', '/');
        let parent = TEMPLATES['layout'] || '';

        // Extract blocks from child
        const blockRegex = /\{%\s*block\s+(\w+)\s*%\}([\s\S]*?)\{%\s*endblock\s*%\}/g;
        const blocks = {};
        let match;
        while ((match = blockRegex.exec(template)) !== null) {
            blocks[match[1]] = match[2];
        }

        // Replace blocks in parent
        template = parent.replace(/\{%\s*block\s+(\w+)\s*%\}[\s\S]*?\{%\s*endblock\s*%\}/g, (m, blockName) => {
            return blocks[blockName] || '';
        });
    }

    // Handle {% include 'components/...' %}
    template = template.replace(/\{%\s*include\s*['"]([^'"]+)['"]\s*%\}/g, (m, includeName) => {
        const name = includeName.replace('.html', '');
        return TEMPLATES[name] || '';
    });

    // Handle {{ variable }} - simple replacement
    template = template.replace(/\{\{\s*(\w+(?:\.\w+)*)\s*\}\}/g, (m, key) => {
        const keys = key.split('.');
        let val = context;
        for (const k of keys) {
            val = val?.[k];
        }
        return val !== undefined ? String(val) : '';
    });

    // Handle {% for item in items %}...{% endfor %}
    template = template.replace(/\{%\s*for\s+(\w+)\s+in\s+(\w+)\s*%\}([\s\S]*?)\{%\s*endfor\s*%\}/g, (m, itemName, listName, content) => {
        const list = context[listName] || [];
        return list.map(item => {
            let itemContent = content;
            // Replace {{ item.prop }} and {{ item }}
            itemContent = itemContent.replace(/\{\{\s*(\w+)\.(\w+)\s*\}\}/g, (m2, varName, prop) => {
                if (varName === itemName) {
                    return item[prop] !== undefined ? String(item[prop]) : '';
                }
                return m2;
            });
            itemContent = itemContent.replace(/\{\{\s*(\w+)\s*\}\}/g, (m2, varName) => {
                if (varName === itemName) {
                    return typeof item === 'object' ? JSON.stringify(item) : String(item);
                }
                return context[varName] !== undefined ? String(context[varName]) : '';
            });
            return itemContent;
        }).join('');
    });

    // Handle {% if condition %}...{% endif %} and {% if condition %}...{% else %}...{% endif %}
    template = template.replace(/\{%\s*if\s+(.+?)\s*%\}([\s\S]*?)\{%\s*endif\s*%\}/g, (m, condition, content) => {
        // Split by else
        const elseParts = content.split(/\{%\s*else\s*%\}/);
        const ifContent = elseParts[0];
        const elseContent = elseParts[1] || '';

        // Evaluate simple conditions
        let result = false;

        // Handle "not variable"
        if (condition.startsWith('not ')) {
            const varName = condition.slice(4).trim();
            result = !context[varName];
        }
        // Handle "variable == 'value'"
        else if (condition.includes('==')) {
            const [left, right] = condition.split('==').map(s => s.trim());
            const leftVal = context[left] !== undefined ? context[left] : left;
            const rightVal = right.replace(/['"]/g, '');
            result = leftVal == rightVal;
        }
        // Handle "variable != 'value'"
        else if (condition.includes('!=')) {
            const [left, right] = condition.split('!=').map(s => s.trim());
            const leftVal = context[left] !== undefined ? context[left] : left;
            const rightVal = right.replace(/['"]/g, '');
            result = leftVal != rightVal;
        }
        // Handle simple variable
        else {
            const varName = condition.trim();
            result = !!context[varName];
        }

        return result ? ifContent : elseContent;
    });

    // Handle url_for - replace with actual URLs
    template = template.replace(/\{\{\s*url_for\s*\(\s*['"](\w+)['"]\s*(?:,\s*(\w+)\s*=\s*(\w+(?:\.\w+)*))?\s*\)\s*\}\}/g, (m, routeName, paramName, paramValue) => {
        const routes = {
            'login': '/',
            'register': '/register',
            'logout': '/logout',
            'superadmin_dashboard': '/superadmin',
            'superadmin_profile': '/superadmin/profile',
            'superadmin_update_profile': '/superadmin/update',
            'superadmin_create_event': '/superadmin/event/create',
            'staff_events': '/staff/events',
            'staff_profile': '/staff/profile',
            'staff_update_profile': '/staff/update',
            'qr_code_route': '/qr_code',
            'view_logs': '/staff/event',
        };
        let url = routes[routeName] || `/${routeName}`;
        if (paramName && paramValue) {
            const keys = paramValue.split('.');
            let val = context;
            for (const k of keys) {
                val = val?.[k];
            }
            url += `/${val}`;
        }
        return url;
    });

    // Clean up remaining Jinja syntax
    template = template.replace(/\{%[\s\S]*?%\}/g, '');
    template = template.replace(/\{\{[\s\S]*?\}\}/g, '');

    return template;
}

// ============================
// SESSION HELPERS
// ============================

function getSession(c) {
    const sessionData = getCookie(c, 'session');
    if (sessionData) {
        try {
            return JSON.parse(atob(sessionData));
        } catch {
            return {};
        }
    }
    return {};
}

function setSession(c, data) {
    const encoded = btoa(JSON.stringify(data));
    setCookie(c, 'session', encoded, {
        path: '/',
        httpOnly: true,
        secure: true,
        maxAge: 86400 * 7
    });
}

function clearSession(c) {
    deleteCookie(c, 'session', { path: '/' });
}

// ============================
// DATABASE HELPERS
// ============================

async function getUser(db, username) {
    return await db.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
}

// ============================
// ROUTES
// ============================

// Login Page
app.get('/', async (c) => {
    const session = getSession(c);
    if (session.username) {
        return c.redirect(session.role === 'superadmin' ? '/superadmin' : '/staff/events');
    }
    const user = null;
    return c.html(render('login', { user, flash_messages: [] }));
});

app.post('/', async (c) => {
    const body = await c.req.parseBody();
    const db = c.env.DB;
    const user = await getUser(db, body.username);

    if (user && user.password === body.password) {
        if (user.approved === 0) {
            return c.html(render('pending', {}));
        }
        setSession(c, { username: user.username, role: user.role, name: user.name });
        return c.redirect(user.role === 'superadmin' ? '/superadmin' : '/staff/events');
    }
    return c.html(render('login', { user: null, flash_messages: [{ category: 'error', message: 'Invalid credentials.' }] }));
});

// Register Page
app.get('/register', (c) => {
    return c.html(render('register', { user: null, flash_messages: [] }));
});

app.post('/register', async (c) => {
    const body = await c.req.parseBody();
    const db = c.env.DB;

    const existing = await getUser(db, body.username);
    if (existing) {
        return c.html(render('register', { user: null, flash_messages: [{ category: 'error', message: 'Username already taken.' }] }));
    }

    await db.prepare("INSERT INTO users (username, password, role, name, phone, address, approved) VALUES (?, ?, 'staff', ?, ?, ?, 0)")
        .bind(body.username, body.password, body.name, body.phone, body.address).run();

    return c.redirect('/');
});

// Logout
app.get('/logout', (c) => {
    clearSession(c);
    return c.redirect('/');
});

// Superadmin Dashboard
app.get('/superadmin', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');

    const db = c.env.DB;
    const user = await getUser(db, session.username);
    const pending_staff = (await db.prepare("SELECT * FROM users WHERE role != 'superadmin' AND approved = 0").all()).results || [];
    const approved_staff = (await db.prepare("SELECT * FROM users WHERE role != 'superadmin' AND approved = 1").all()).results || [];
    const all_events = (await db.prepare("SELECT e.*, COUNT(ea.id) as staff_count FROM events e LEFT JOIN event_admins ea ON e.event_id = ea.event_id GROUP BY e.event_id").all()).results || [];

    return c.html(render('superadmin/dashboard', { user, pending_staff, approved_staff, all_events, flash_messages: [] }));
});

// Superadmin - Create Event
app.post('/superadmin/event/create', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');

    const body = await c.req.parseBody();
    const db = c.env.DB;
    await db.prepare("INSERT INTO events (event_name) VALUES (?)").bind(body.event_name).run();
    return c.redirect('/superadmin');
});

// Superadmin - Approve Staff
app.post('/superadmin/approve/:username', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');

    const db = c.env.DB;
    await db.prepare("UPDATE users SET approved = 1 WHERE username = ?").bind(c.req.param('username')).run();
    return c.redirect('/superadmin');
});

// Superadmin - Delete Staff
app.post('/superadmin/delete/:username', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');

    const db = c.env.DB;
    await db.prepare("DELETE FROM users WHERE username = ?").bind(c.req.param('username')).run();
    await db.prepare("DELETE FROM event_admins WHERE admin_username = ?").bind(c.req.param('username')).run();
    return c.redirect('/superadmin');
});

// Superadmin - Delete Event
app.post('/superadmin/event/delete/:event_id', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');

    const eventId = c.req.param('event_id');
    const db = c.env.DB;
    await db.prepare("DELETE FROM events WHERE event_id = ?").bind(eventId).run();
    await db.prepare("DELETE FROM event_fields WHERE event_id = ?").bind(eventId).run();
    await db.prepare("DELETE FROM event_admins WHERE event_id = ?").bind(eventId).run();
    await db.prepare("DELETE FROM logs WHERE event_id = ?").bind(eventId).run();
    return c.redirect('/superadmin');
});

// Superadmin - Manage Event Staff
app.get('/superadmin/event/staff/:event_id', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');

    const eventId = c.req.param('event_id');
    const db = c.env.DB;
    const user = await getUser(db, session.username);
    const event = await db.prepare("SELECT * FROM events WHERE event_id = ?").bind(eventId).first();
    if (!event) return c.redirect('/superadmin');

    const assigned_staff = (await db.prepare("SELECT u.* FROM users u JOIN event_admins ea ON u.username = ea.admin_username WHERE ea.event_id = ?").bind(eventId).all()).results || [];
    const unassigned_staff = (await db.prepare("SELECT * FROM users WHERE role != 'superadmin' AND approved = 1 AND username NOT IN (SELECT admin_username FROM event_admins WHERE event_id = ?)").bind(eventId).all()).results || [];

    return c.html(render('superadmin/manage_staff', { user, event, assigned_staff, unassigned_staff, flash_messages: [] }));
});

// Superadmin - Add Staff to Event
app.post('/superadmin/event/staff/add/:event_id/:username', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');

    const db = c.env.DB;
    await db.prepare("INSERT INTO event_admins (event_id, admin_username) VALUES (?, ?)").bind(c.req.param('event_id'), c.req.param('username')).run();
    return c.redirect(`/superadmin/event/staff/${c.req.param('event_id')}`);
});

// Superadmin - Remove Staff from Event
app.post('/superadmin/event/staff/remove/:event_id/:username', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');

    const db = c.env.DB;
    await db.prepare("DELETE FROM event_admins WHERE event_id = ? AND admin_username = ?").bind(c.req.param('event_id'), c.req.param('username')).run();
    return c.redirect(`/superadmin/event/staff/${c.req.param('event_id')}`);
});

// Superadmin - Edit Event Form
app.get('/superadmin/event/edit/:event_id', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');

    const eventId = c.req.param('event_id');
    const db = c.env.DB;
    const user = await getUser(db, session.username);
    const event = await db.prepare("SELECT * FROM events WHERE event_id = ?").bind(eventId).first();
    const fields = (await db.prepare("SELECT * FROM event_fields WHERE event_id = ?").bind(eventId).all()).results || [];

    return c.html(render('superadmin/edit_form', { user, event, fields, flash_messages: [] }));
});

app.post('/superadmin/event/edit/:event_id', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');

    const eventId = c.req.param('event_id');
    const body = await c.req.parseBody();
    const db = c.env.DB;

    const isRequired = body.is_required ? 1 : 0;
    await db.prepare("INSERT INTO event_fields (event_id, field_label, field_type, is_required) VALUES (?, ?, ?, ?)")
        .bind(eventId, body.field_label, body.field_type, isRequired).run();

    return c.redirect(`/superadmin/event/edit/${eventId}`);
});

// Superadmin - Delete Field
app.post('/superadmin/field/delete/:field_id', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');

    const db = c.env.DB;
    const field = await db.prepare("SELECT event_id FROM event_fields WHERE field_id = ?").bind(c.req.param('field_id')).first();
    if (field) {
        await db.prepare("DELETE FROM event_fields WHERE field_id = ?").bind(c.req.param('field_id')).run();
        return c.redirect(`/superadmin/event/edit/${field.event_id}`);
    }
    return c.redirect('/superadmin');
});

// Superadmin Profile
app.get('/superadmin/profile', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');

    const db = c.env.DB;
    const user = await getUser(db, session.username);
    return c.html(render('superadmin/profile', { user, flash_messages: [] }));
});

app.post('/superadmin/update', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');

    const body = await c.req.parseBody();
    const db = c.env.DB;

    if (body.password) {
        await db.prepare("UPDATE users SET password = ? WHERE username = ?").bind(body.password, session.username).run();
    }
    return c.redirect('/superadmin/profile');
});

// Staff Events
app.get('/staff/events', async (c) => {
    const session = getSession(c);
    if (!session.username) return c.redirect('/');

    const db = c.env.DB;
    const user = await getUser(db, session.username);
    const result = await db.prepare("SELECT e.* FROM events e JOIN event_admins ea ON e.event_id = ea.event_id WHERE ea.admin_username = ?").bind(session.username).all();

    const events = (result.results || []).map(e => ({
        ...e,
        url: `${c.env.BASE_URL}/attend/${e.event_id}`
    }));

    return c.html(render('staff/events', { user, events, flash_messages: [] }));
});

// Staff Profile
app.get('/staff/profile', async (c) => {
    const session = getSession(c);
    if (!session.username) return c.redirect('/');

    const db = c.env.DB;
    const user = await getUser(db, session.username);
    return c.html(render('staff/profile', { user, flash_messages: [] }));
});

app.post('/staff/update', async (c) => {
    const session = getSession(c);
    if (!session.username) return c.redirect('/');

    const body = await c.req.parseBody();
    const db = c.env.DB;

    let query = "UPDATE users SET name = ?, phone = ?, address = ?";
    const params = [body.name, body.phone, body.address];

    if (body.password) {
        query += ", password = ?";
        params.push(body.password);
    }

    query += " WHERE username = ?";
    params.push(session.username);

    await db.prepare(query).bind(...params).run();
    return c.redirect('/staff/profile');
});

// Staff - View Logs
app.get('/staff/event/:event_id/logs', async (c) => {
    const session = getSession(c);
    if (!session.username) return c.redirect('/');

    const eventId = c.req.param('event_id');
    const db = c.env.DB;
    const user = await getUser(db, session.username);

    // Check access
    if (session.role !== 'superadmin') {
        const access = await db.prepare("SELECT 1 FROM event_admins WHERE event_id = ? AND admin_username = ?").bind(eventId, session.username).first();
        if (!access) return c.redirect('/staff/events');
    }

    const event = await db.prepare("SELECT * FROM events WHERE event_id = ?").bind(eventId).first();
    const fields = (await db.prepare("SELECT * FROM event_fields WHERE event_id = ? ORDER BY field_order ASC").bind(eventId).all()).results || [];
    const logsRaw = (await db.prepare("SELECT * FROM logs WHERE event_id = ? ORDER BY log_id DESC LIMIT 50").bind(eventId).all()).results || [];

    const logs = logsRaw.map(l => {
        try {
            l.data = JSON.parse(l.data);
        } catch { l.data = {}; }
        return l;
    });

    const countResult = await db.prepare("SELECT COUNT(*) as count FROM logs WHERE event_id = ?").bind(eventId).first();
    const log_count = countResult?.count || 0;

    return c.html(render('staff/logs', { user, event, fields, logs, log_count, flash_messages: [] }));
});

// Staff - Delete Log
app.post('/staff/log/delete/:log_id/:event_id', async (c) => {
    const session = getSession(c);
    if (!session.username) return c.redirect('/');

    const db = c.env.DB;
    await db.prepare("DELETE FROM logs WHERE log_id = ?").bind(c.req.param('log_id')).run();
    return c.redirect(`/staff/event/${c.req.param('event_id')}/logs`);
});

// Public - Attend Event
app.get('/attend/:event_id', async (c) => {
    const eventId = c.req.param('event_id');
    const db = c.env.DB;

    const event = await db.prepare("SELECT * FROM events WHERE event_id = ?").bind(eventId).first();
    if (!event) return c.text('Event not found', 404);

    const fields = (await db.prepare("SELECT * FROM event_fields WHERE event_id = ? ORDER BY field_order ASC").bind(eventId).all()).results || [];

    return c.html(render('attend', { event, fields, flash_messages: [] }));
});

app.post('/attend/:event_id', async (c) => {
    const eventId = c.req.param('event_id');
    const db = c.env.DB;
    const body = await c.req.parseBody();

    const event = await db.prepare("SELECT * FROM events WHERE event_id = ?").bind(eventId).first();
    if (!event) return c.text('Event not found', 404);

    const fields = (await db.prepare("SELECT * FROM event_fields WHERE event_id = ?").bind(eventId).all()).results || [];

    const data = {};
    for (const field of fields) {
        data[field.field_label] = body[field.field_label] || '';
    }

    const now = new Date();
    const timestamp = now.toISOString();

    await db.prepare("INSERT INTO logs (event_id, data, timestamp) VALUES (?, ?, ?)").bind(eventId, JSON.stringify(data), timestamp).run();

    const formattedTime = now.toLocaleString('en-US', {
        year: 'numeric', month: 'long', day: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true
    });

    return c.html(render('attend_success', { event, timestamp: formattedTime }));
});

// QR Code
app.get('/qr_code/:event_id', async (c) => {
    const eventId = c.req.param('event_id');
    const url = `${c.env.BASE_URL}/attend/${eventId}`;

    const qrApiUrl = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(url)}`;
    const response = await fetch(qrApiUrl);

    return new Response(await response.arrayBuffer(), {
        headers: { 'Content-Type': 'image/png' }
    });
});

// API - Event Logs
app.get('/api/event/:event_id/logs', async (c) => {
    const session = getSession(c);
    if (!session.username) return c.json({ error: 'Unauthorized' }, 401);

    const eventId = c.req.param('event_id');
    const sinceId = parseInt(c.req.query('since') || '0');
    const db = c.env.DB;

    const logsRaw = (await db.prepare("SELECT * FROM logs WHERE event_id = ? AND log_id > ? ORDER BY log_id DESC").bind(eventId, sinceId).all()).results || [];

    const logs = logsRaw.map(l => {
        try { l.data = JSON.parse(l.data); } catch { l.data = {}; }
        try {
            const dt = new Date(l.timestamp);
            l.formatted_timestamp = dt.toLocaleString('en-GB', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
        } catch { l.formatted_timestamp = l.timestamp; }
        return l;
    });

    return c.json({ logs });
});

// Queue Status (compatibility)
app.get('/queue_status', (c) => {
    return c.json({ size: 0 });
});

// Static files
app.get('/static/*', async (c) => {
    const path = c.req.path.replace('/static/', '');
    // Cloudflare will serve from the [site] bucket
    return c.notFound();
});

export default app;
