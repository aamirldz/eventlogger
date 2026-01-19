import { Hono } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';

const app = new Hono();

// ============================
// TEMPLATES AS RAW HTML (imported as text modules)
// ============================

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

// ============================
// TEMPLATE ENGINE (Jinja2-compatible)
// ============================

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function render(templateName, context = {}) {
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

    let template = TEMPLATES[templateName] || '';

    // Remove Jinja2 comments {# ... #} first (they can span multiple lines)
    template = template.replace(/\{#[\s\S]*?#\}/g, '');

    // Resolve includes first
    template = template.replace(/\{%\s*include\s+['"]([^'"]+)['"]\s*%\}/g, (match, includePath) => {
        const name = includePath.replace('.html', '').replace('components/', 'components/');
        let included = TEMPLATES[name] || '';
        // Remove comments from included template
        included = included.replace(/\{#[\s\S]*?#\}/g, '');
        return included;
    });

    // Handle extends and blocks
    const extendsMatch = template.match(/\{%\s*extends\s+['"]([^'"]+)['"]\s*%\}/);
    if (extendsMatch) {
        let layout = TEMPLATES['layout'] || '';

        // Extract all blocks from child template
        const blocks = {};
        const blockRegex = /\{%\s*block\s+(\w+)\s*%\}([\s\S]*?)\{%\s*endblock\s*%\}/g;
        let match;
        while ((match = blockRegex.exec(template)) !== null) {
            blocks[match[1]] = match[2].trim();
        }

        // Replace blocks in layout with child content
        template = layout.replace(/\{%\s*block\s+(\w+)\s*%\}[\s\S]*?\{%\s*endblock\s*%\}/g, (m, blockName) => {
            return blocks[blockName] !== undefined ? blocks[blockName] : '';
        });

        // Re-resolve includes after extends
        template = template.replace(/\{%\s*include\s+['"]([^'"]+)['"]\s*%\}/g, (match, includePath) => {
            const name = includePath.replace('.html', '').replace('components/', 'components/');
            let included = TEMPLATES[name] || '';
            // Remove comments from included template
            included = included.replace(/\{#[\s\S]*?#\}/g, '');
            return included;
        });

        // Remove any remaining comments after layout processing
        template = template.replace(/\{#[\s\S]*?#\}/g, '');
    }

    // Handle url_for
    template = template.replace(/\{\{\s*url_for\s*\(['"]static['"]\s*,\s*filename\s*=\s*['"]([^'"]+)['"]\s*\)\s*\}\}/g, '/static/$1');
    template = template.replace(/\{\{\s*url_for\s*\(['"]([^'"]+)['"]\s*\)\s*\}\}/g, (m, route) => {
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
        };
        return routes[route] || '/' + route;
    });

    // Handle url_for with parameters
    template = template.replace(/\{\{\s*url_for\s*\(['"]([^'"]+)['"]\s*,\s*(\w+)\s*=\s*([^)]+)\s*\)\s*\}\}/g, (m, route, param, value) => {
        // Get value from context
        const keys = value.trim().split('.');
        let val = context;
        for (const k of keys) {
            val = val?.[k];
        }

        const routes = {
            'superadmin_manage_event_staff': `/superadmin/event/staff/${val}`,
            'superadmin_edit_event_form': `/superadmin/event/edit/${val}`,
            'superadmin_delete_event': `/superadmin/event/delete/${val}`,
            'superadmin_approve_staff': `/superadmin/approve/${val}`,
            'superadmin_delete_staff': `/superadmin/delete/${val}`,
            'superadmin_add_event_staff': `/superadmin/event/staff/add`,
            'superadmin_remove_event_staff': `/superadmin/event/staff/remove`,
            'view_logs': `/staff/event/${val}/logs`,
            'qr_code_route': `/qr_code/${val}`,
            'delete_log': `/staff/log/delete`,
            'superadmin_delete_field': `/superadmin/field/delete/${val}`,
            'uploaded_file': `/uploads/${val}`,
            'attend_event': `/attend/${val}`,
        };
        return routes[route] || '/' + route + '/' + val;
    });

    // Handle flash messages (with block)
    template = template.replace(/\{%\s*with\s+messages\s*=\s*get_flashed_messages\([^)]*\)\s*%\}[\s\S]*?\{%\s*endwith\s*%\}/g, () => {
        const messages = context.flash_messages || [];
        if (messages.length === 0) return '';
        return messages.map(msg => {
            if (msg.category === 'error') {
                return `<div class="bg-red-900/50 border border-red-500 text-red-200 px-4 py-3 rounded-lg relative mb-6" role="alert"><span class="block sm:inline">${escapeHtml(msg.message)}</span></div>`;
            }
            return `<div class="bg-green-900/50 border border-green-500 text-green-200 px-4 py-3 rounded-lg relative mb-6" role="alert"><span class="block sm:inline">${escapeHtml(msg.message)}</span></div>`;
        }).join('');
    });

    // Handle for loops
    template = template.replace(/\{%\s*for\s+(\w+)\s+in\s+(\w+)\s*%\}([\s\S]*?)\{%\s*endfor\s*%\}/g, (m, itemVar, listVar, content) => {
        const list = context[listVar] || [];
        return list.map(item => {
            let itemContent = content;
            // Replace item.property
            itemContent = itemContent.replace(new RegExp(`\\{\\{\\s*${itemVar}\\.(\\w+)\\s*\\}\\}`, 'g'), (m2, prop) => {
                return escapeHtml(item[prop]);
            });
            itemContent = itemContent.replace(new RegExp(`\\{\\{\\s*${itemVar}\\['(\\w+)'\\]\\s*\\}\\}`, 'g'), (m2, prop) => {
                return escapeHtml(item[prop]);
            });
            // Replace item alone
            itemContent = itemContent.replace(new RegExp(`\\{\\{\\s*${itemVar}\\s*\\}\\}`, 'g'), escapeHtml(JSON.stringify(item)));

            // Handle url_for with item properties
            itemContent = itemContent.replace(/\{\{\s*url_for\s*\(['"]([^'"]+)['"]\s*,\s*(\w+)\s*=\s*(\w+)\.(\w+)\s*\)\s*\}\}/g, (m3, route, param, varName, prop) => {
                if (varName === itemVar) {
                    const val = item[prop];
                    const routes = {
                        'superadmin_manage_event_staff': `/superadmin/event/staff/${val}`,
                        'superadmin_edit_event_form': `/superadmin/event/edit/${val}`,
                        'superadmin_delete_event': `/superadmin/event/delete/${val}`,
                        'superadmin_approve_staff': `/superadmin/approve/${val}`,
                        'superadmin_delete_staff': `/superadmin/delete/${val}`,
                        'view_logs': `/staff/event/${val}/logs`,
                        'qr_code_route': `/qr_code/${val}`,
                        'superadmin_delete_field': `/superadmin/field/delete/${val}`,
                        'uploaded_file': `/uploads/${val}`,
                    };
                    return routes[route] || '/' + route + '/' + val;
                }
                return m3;
            });

            // Handle url_for with multiple params
            itemContent = itemContent.replace(/\{\{\s*url_for\s*\(['"]([^'"]+)['"]\s*,\s*event_id\s*=\s*event\.event_id\s*,\s*username\s*=\s*(\w+)\.username\s*\)\s*\}\}/g, (m3, route, varName) => {
                if (varName === itemVar) {
                    const eventId = context.event?.event_id;
                    const username = item.username;
                    if (route === 'superadmin_add_event_staff') return `/superadmin/event/staff/add/${eventId}/${username}`;
                    if (route === 'superadmin_remove_event_staff') return `/superadmin/event/staff/remove/${eventId}/${username}`;
                }
                return m3;
            });

            return itemContent;
        }).join('');
    });

    // Handle if/else statements
    function processIfs(tmpl, ctx) {
        let result = tmpl;
        let changed = true;
        let iterations = 0;

        while (changed && iterations < 10) {
            changed = false;
            iterations++;

            result = result.replace(/\{%\s*if\s+(.+?)\s*%\}([\s\S]*?)\{%\s*endif\s*%\}/g, (m, condition, content) => {
                changed = true;
                const elseParts = content.split(/\{%\s*else\s*%\}/);
                const ifContent = elseParts[0] || '';
                const elseContent = elseParts[1] || '';

                let condResult = evaluateCondition(condition.trim(), ctx);
                return condResult ? ifContent : elseContent;
            });
        }

        return result;
    }

    function evaluateCondition(cond, ctx) {
        // Handle "not variable"
        if (cond.startsWith('not ')) {
            return !evaluateCondition(cond.slice(4).trim(), ctx);
        }
        // Handle "a == b"
        if (cond.includes(' == ')) {
            const [left, right] = cond.split(' == ').map(s => s.trim());
            const leftVal = getContextValue(left, ctx);
            const rightVal = right.replace(/['"]/g, '');
            return leftVal == rightVal;
        }
        // Handle "a != b"
        if (cond.includes(' != ')) {
            const [left, right] = cond.split(' != ').map(s => s.trim());
            const leftVal = getContextValue(left, ctx);
            const rightVal = right.replace(/['"]/g, '');
            return leftVal != rightVal;
        }
        // Handle "a and b"
        if (cond.includes(' and ')) {
            const parts = cond.split(' and ').map(s => s.trim());
            return parts.every(p => evaluateCondition(p, ctx));
        }
        // Handle "a or b"
        if (cond.includes(' or ')) {
            const parts = cond.split(' or ').map(s => s.trim());
            return parts.some(p => evaluateCondition(p, ctx));
        }
        // Simple variable check
        return !!getContextValue(cond, ctx);
    }

    function getContextValue(path, ctx) {
        const parts = path.replace(/\[['"](\w+)['"]\]/g, '.$1').split('.');
        let val = ctx;
        for (const p of parts) {
            if (val === undefined || val === null) return undefined;
            val = val[p];
        }
        return val;
    }

    template = processIfs(template, context);

    // Handle simple variable replacement
    template = template.replace(/\{\{\s*([a-zA-Z_][\w.]*(?:\['[^']+'\])?)\s*\}\}/g, (m, varPath) => {
        const val = getContextValue(varPath, context);
        return val !== undefined ? escapeHtml(val) : '';
    });

    // Handle filters like |safe
    template = template.replace(/\{\{\s*([^}|]+)\s*\|\s*safe\s*\}\}/g, (m, varPath) => {
        const val = getContextValue(varPath.trim(), context);
        return val !== undefined ? String(val) : '';
    });

    // Clean up any remaining Jinja2 syntax
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
    setCookie(c, 'session', encoded, { path: '/', httpOnly: true, secure: true, maxAge: 86400 * 7 });
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

// Static files - serve CSS (embedded directly to avoid module import issues)
const styleCss = `:root{--cyber-green:#00ff9c;--cyber-green-dark:#00b894;--cyber-glow:rgba(0,255,156,0.2);--cyber-glow-heavy:rgba(0,255,156,0.5);--tech-blue:rgba(173,216,230,0.2)}*{-webkit-tap-highlight-color:transparent;box-sizing:border-box}html{height:100%;scroll-behavior:smooth}body{font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;color:#e0e0e0;background-color:#090a0f;background-image:radial-gradient(ellipse at bottom,#1b2735 0%,#090a0f 100%);min-height:100%;overflow-x:hidden;position:relative;-webkit-font-smoothing:antialiased}@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;transition-duration:.01ms!important}}#stars-container{position:fixed;top:0;left:0;width:100%;height:100%;z-index:0;overflow:hidden;will-change:transform}#stars1,#stars2,#stars3{will-change:transform}#stars1{width:1px;height:1px;background:transparent;box-shadow:714px 1729px #fff,1920px 796px #fff,908px 117px #fff,1695px 1198px #fff,608px 879px #fff,1604px 1728px #fff,1172px 147px #fff,1450px 731px #fff,1461px 1827px #fff,1318px 1269px #fff;animation:stars 50s linear infinite}#stars2{width:2px;height:2px;background:transparent;box-shadow:1828px 1563px #fff,1078px 1284px #fff,100px 1413px #fff,735px 722px #fff,1133px 801px #fff,144px 1311px #fff,1435px 326px #fff,1404px 555px #fff,1530px 1538px #fff,1515px 1275px #fff;animation:stars 100s linear infinite}#stars3{width:3px;height:3px;background:transparent;box-shadow:1530px 583px #fff,1824px 1313px #fff,20px 321px #fff,1020px 1868px #fff,1148px 1633px #fff,1244px 383px #fff,574px 1068px #fff,1111px 112px #fff,1599px 1008px #fff,1472px 1620px #fff;animation:stars 150s linear infinite}@keyframes stars{from{transform:translateY(0)}to{transform:translateY(-2000px)}}.hex-overlay{position:fixed;top:0;left:0;width:100%;height:100%;z-index:1;background-image:linear-gradient(rgba(0,255,156,.05) 1px,transparent 1px),linear-gradient(60deg,rgba(0,255,156,.05) 1px,transparent 1px),linear-gradient(120deg,rgba(0,255,156,.05) 1px,transparent 1px);background-size:36px 62px;opacity:.5;animation:panGrid 15s linear infinite;pointer-events:none}@media(max-width:768px){.hex-overlay{opacity:.3;animation:none}}@keyframes panGrid{0%{background-position:0 0}100%{background-position:0 62px}}.card{background-color:rgba(30,30,50,.5);border:1px solid var(--tech-blue);border-radius:1rem;backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);box-shadow:0 8px 32px 0 rgba(0,0,0,.37);transition:all .3s ease}@media(hover:hover){.card:hover{transform:translateY(-5px);border-color:var(--cyber-green);box-shadow:0 12px 40px 0 rgba(0,0,0,.5),0 0 20px 0 var(--cyber-glow)}}.form-input{background-color:rgba(0,0,0,.3);border:1px solid rgba(255,255,255,.2);color:#fff;border-radius:.5rem;transition:all .3s ease;font-size:16px}.form-input:focus{outline:none;border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.4);background-color:rgba(0,0,0,.5)}.form-input::placeholder{color:#777}.btn{position:relative;overflow:hidden;padding:.75rem 1.5rem;border-radius:.5rem;font-weight:600;color:#fff;text-align:center;transition:all .2s ease;box-shadow:0 4px 15px rgba(0,0,0,.2);border:none;cursor:pointer;min-height:44px;display:inline-flex;align-items:center;justify-content:center;text-decoration:none}@media(hover:hover){.btn:hover{transform:scale(1.05);box-shadow:0 6px 20px rgba(0,0,0,.3)}}.btn:active{transform:scale(.98);opacity:.9}.btn-primary{background-image:linear-gradient(to right,#00c6ff,#0072ff)}.btn-cyber-green{background-image:linear-gradient(to right,var(--cyber-green),var(--cyber-green-dark));color:#0a0a0f}.btn-green{background-image:linear-gradient(to right,#10b981,#059669)}.btn-danger{background-image:linear-gradient(to right,#ef4444,#dc2626)}.btn-warning{background-image:linear-gradient(to right,#f59e0b,#d97706)}.btn-purple{background-image:linear-gradient(to right,#8b5cf6,#6d28d9)}.btn-ghost{background-color:transparent;border:1px solid rgba(255,255,255,.3);color:#e0e0e0}.btn-ghost:hover{background-color:rgba(255,255,255,.1)}@media(max-width:640px){.btn{padding:.6rem 1rem;font-size:.875rem}}@keyframes highlightRow{0%{background-color:rgba(0,255,156,.3)}100%{background-color:transparent}}.log-row-new{animation:highlightRow 2.5s ease-out}.dark-table{width:100%;overflow-x:auto;display:block}.dark-table thead{background-color:rgba(0,0,0,.3)}.dark-table th{color:#a0a0a0;white-space:nowrap}.dark-table tbody{border-color:rgba(255,255,255,.2)}.dark-table tr{border-color:rgba(255,255,255,.2);transition:background-color .2s}.dark-table tr:hover{background-color:rgba(255,255,255,.05)}.dark-table td{color:#d0d0d0}.dark-table .data-cell{color:#fff;font-weight:500}.log-row.hidden{display:none}.robot-container{display:flex;justify-content:center;align-items:center;filter:drop-shadow(0 0 15px rgba(0,255,156,.3))}.robot-head,.robot-body{will-change:transform;animation:bob 4s ease-in-out infinite}.robot-body{animation-delay:-.1s}.robot-core{animation:pulse-core 2s ease-in-out infinite alternate}.robot-hand-left{animation:float-hand 3s ease-in-out infinite alternate}.robot-hand-right{animation:float-hand 3.2s ease-in-out infinite alternate}@keyframes bob{0%,100%{transform:translateY(0)}50%{transform:translateY(-10px)}}@keyframes pulse-core{from{fill:var(--cyber-green);filter:drop-shadow(0 0 5px var(--cyber-green))}to{fill:#fff;filter:drop-shadow(0 0 15px #fff)}}@keyframes float-hand{from{transform:translateY(-5px) rotate(-5deg)}to{transform:translateY(5px) rotate(5deg)}}.robot-shoulder-ring{animation:float-hand 3.5s ease-in-out infinite alternate}.robot-hand-glow{animation:float-hand 3s ease-in-out infinite alternate;filter:drop-shadow(0 0 5px var(--cyber-green))}.robot-visor-scan{animation:scan-light 4s ease-in-out infinite}.robot-core-glow{animation:pulse-core 2s ease-in-out infinite alternate}.robot-antenna-tip{animation:pulse-core 1.5s ease-in-out infinite alternate}.robot-logo-text{font-family:monospace;font-weight:700;font-size:16px;fill:#fff;letter-spacing:.1em}.robot-logo-glow{filter:drop-shadow(0 0 6px var(--cyber-green))}@keyframes scan-light{0%,100%{transform:translateX(-60px);opacity:.3}50%{transform:translateX(60px);opacity:1}}.bg-cyber-green{background-color:var(--cyber-green)}.shadow-cyber-green{box-shadow:0 0 8px 2px var(--cyber-glow-heavy)}.profile-avatar-link{transition:transform .2s ease,box-shadow .2s ease;display:inline-block}@media(hover:hover){.profile-avatar-link:hover{transform:scale(1.1);box-shadow:0 0 12px rgba(59,130,246,.5)}}.badge-super{background-color:#f59e0b;color:#78350f;font-size:.65rem;font-weight:700;padding:.125rem .5rem;border-radius:9999px;margin-right:.5rem}@media(max-width:640px){h1{font-size:1.75rem!important}h2{font-size:1.5rem!important}h3{font-size:1.25rem!important}.card{border-radius:.75rem}}@keyframes spin{to{transform:rotate(360deg)}}.animate-spin{animation:spin 1s linear infinite}`;

app.get('/static/css/style.css', (c) => {
    return new Response(styleCss, {
        headers: {
            'Content-Type': 'text/css',
            'Cache-Control': 'public, max-age=31536000'
        }
    });
});

// Login
app.get('/', async (c) => {
    const session = getSession(c);
    if (session.username) {
        return c.redirect(session.role === 'superadmin' ? '/superadmin' : '/staff/events');
    }
    return c.html(render('login', { user: null, flash_messages: [] }));
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

// Register
app.get('/register', (c) => c.html(render('register', { user: null, flash_messages: [] })));

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
    const events = (result.results || []).map(e => ({ ...e, url: `${c.env.BASE_URL}/attend/${e.event_id}` }));
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
    if (body.password) { query += ", password = ?"; params.push(body.password); }
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
    if (session.role !== 'superadmin') {
        const access = await db.prepare("SELECT 1 FROM event_admins WHERE event_id = ? AND admin_username = ?").bind(eventId, session.username).first();
        if (!access) return c.redirect('/staff/events');
    }
    const event = await db.prepare("SELECT * FROM events WHERE event_id = ?").bind(eventId).first();
    const fields = (await db.prepare("SELECT * FROM event_fields WHERE event_id = ? ORDER BY field_order ASC").bind(eventId).all()).results || [];
    const logsRaw = (await db.prepare("SELECT * FROM logs WHERE event_id = ? ORDER BY log_id DESC LIMIT 50").bind(eventId).all()).results || [];
    const logs = logsRaw.map(l => { try { l.data = JSON.parse(l.data); } catch { l.data = {}; } return l; });
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
    for (const field of fields) { data[field.field_label] = body[field.field_label] || ''; }
    const now = new Date();
    await db.prepare("INSERT INTO logs (event_id, data, timestamp) VALUES (?, ?, ?)").bind(eventId, JSON.stringify(data), now.toISOString()).run();
    const formattedTime = now.toLocaleString('en-US', { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
    return c.html(render('attend_success', { event, timestamp: formattedTime }));
});

// QR Code
app.get('/qr_code/:event_id', async (c) => {
    const eventId = c.req.param('event_id');
    const url = `${c.env.BASE_URL}/attend/${eventId}`;
    const qrApiUrl = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(url)}`;
    const response = await fetch(qrApiUrl);
    return new Response(await response.arrayBuffer(), { headers: { 'Content-Type': 'image/png' } });
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
        try { l.formatted_timestamp = new Date(l.timestamp).toLocaleString('en-GB'); } catch { l.formatted_timestamp = l.timestamp; }
        return l;
    });
    return c.json({ logs });
});

// Queue Status
app.get('/queue_status', (c) => c.json({ size: 0 }));

// Uploaded files (profile pictures) - placeholder since R2 is disabled
app.get('/uploads/:filename', (c) => {
    // Return a placeholder avatar as profile pics require R2 storage
    return c.redirect('https://api.dicebear.com/7.x/initials/svg?seed=' + c.req.param('filename'));
});

export default app;
