import { Hono } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import QRCode from 'qrcode';
import { neon } from '@neondatabase/serverless';

const app = new Hono();

app.onError((err, c) => {
    console.error('Unhandled Error:', err);
    if (err.message && (err.message.includes('daily row read limit') || err.message.includes('exceeded D1'))) {
        return c.html(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Cloudflare D1 Quota Notice - EventLogger</title>
                <script src="https://cdn.tailwindcss.com"></script>
                <style>body { background: #090a0f; color: #e0e0e0; font-family: 'Inter', sans-serif; }</style>
            </head>
            <body class="min-h-screen flex items-center justify-center p-4">
                <div class="max-w-md w-full bg-gray-900/90 border border-yellow-500/40 rounded-2xl p-8 text-center shadow-2xl backdrop-blur-md">
                    <div class="w-16 h-16 bg-yellow-500/20 text-yellow-400 rounded-full flex items-center justify-center mx-auto mb-4 text-3xl font-bold">⚠️</div>
                    <h2 class="text-2xl font-bold text-white mb-2">Cloudflare D1 Quota Limit</h2>
                    <p class="text-gray-300 text-sm mb-4">
                        Your Cloudflare account's free tier daily row read limit has been reached today by your active apps.
                    </p>
                    <div class="bg-yellow-950/40 border border-yellow-700/50 p-3 rounded-lg mb-6 text-xs font-mono text-yellow-300">
                        Resets automatically at 00:00 UTC (~5.5 hours)
                    </div>
                    <div class="text-left bg-gray-800/80 p-4 rounded-lg text-xs text-gray-300 space-y-2 border border-gray-700">
                        <p class="font-semibold text-white">💻 For immediate unlimited local testing & demo:</p>
                        <code class="block text-green-400 font-mono bg-black/60 p-2.5 rounded">npm run dev</code>
                        <p class="text-gray-400 text-[11px]">Opens at <code>http://localhost:8787</code> with simulated local D1.</p>
                    </div>
                </div>
            </body>
            </html>
        `, 503);
    }
    return c.text(`Unhandled Error: ${err.message}\n${err.stack}`, 500);
});

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
import scannerHtml from '../templates/scanner.html';
import userHeaderHtml from '../templates/components/user_header.html';

const TEMPLATES = {
    'layout': layoutHtml,
    'login': loginHtml,
    'register': registerHtml,
    'pending': pendingHtml,
    'attend': attendHtml,
    'attend_success': attendSuccessHtml,
    'scanner': scannerHtml,
    'staff/events': staffEventsHtml,
    'staff/logs': staffLogsHtml,
    'staff/profile': staffProfileHtml,
    'superadmin/dashboard': superadminDashboardHtml,
    'superadmin/edit_form': superadminEditFormHtml,
    'superadmin/manage_staff': superadminManageStaffHtml,
    'superadmin/profile': superadminProfileHtml,
    'components/user_header': userHeaderHtml,
};

// ============================
// TEMPLATE ENGINE (Jinja2-compatible)
// ============================

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function resolveUrl(route, params = {}) {
    const val = params.event_id || params.username || params.field_id || params.log_id || params.filename || '';

    if (route === 'superadmin_add_event_staff') {
        return `/superadmin/event/staff/add/${params.event_id}/${params.username}`;
    }
    if (route === 'superadmin_remove_event_staff') {
        return `/superadmin/event/staff/remove/${params.event_id}/${params.username}`;
    }
    if (route === 'delete_log') {
        return `/staff/log/delete/${params.log_id}/${params.event_id}`;
    }

    const singleParamRoutes = {
        'superadmin_manage_event_staff': `/superadmin/event/staff/${val}`,
        'superadmin_edit_event_form': `/superadmin/event/edit/${val}`,
        'superadmin_delete_event': `/superadmin/event/delete/${val}`,
        'superadmin_approve_staff': `/superadmin/approve/${val}`,
        'superadmin_delete_staff': `/superadmin/delete/${val}`,
        'view_logs': `/staff/event/${val}/logs`,
        'live_scanner': `/scanner/${val}`,
        'ticket_pass': `/pass/${val}`,
        'qr_code_route': `/qr_code/${val}`,
        'superadmin_delete_field': `/superadmin/field/delete/${val}`,
        'uploaded_file': `/uploads/${val}`,
        'attend_event': `/attend/${val}`,
        'static': `/static/${params.filename || val}`,
    };

    if (singleParamRoutes[route]) return singleParamRoutes[route];

    const simpleRoutes = {
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

    return simpleRoutes[route] || (val ? `/${route}/${val}` : `/${route}`);
}

function getValueFromScope(pathStr, scope) {
    if (!pathStr) return undefined;
    const trimmed = pathStr.trim();
    if (trimmed === 'true') return true;
    if (trimmed === 'false') return false;
    if (trimmed === 'null' || trimmed === 'none' || trimmed === 'None') return null;
    if (/^-?\d+(\.\d+)?$/.test(trimmed)) return Number(trimmed);
    if ((trimmed.startsWith("'") && trimmed.endsWith("'")) || (trimmed.startsWith('"') && trimmed.endsWith('"'))) {
        return trimmed.slice(1, -1);
    }

    // Check url_for inside expression
    const urlForMatch = trimmed.match(/^url_for\s*\(\s*['"]([^'"]+)['"](?:\s*,\s*([\s\S]+))?\s*\)$/);
    if (urlForMatch) {
        const route = urlForMatch[1];
        const paramsStr = urlForMatch[2];
        const params = {};
        if (paramsStr) {
            const paramRegex = /(\w+)\s*=\s*(['"][^'"]*['"]|[^,]+)/g;
            let m;
            while ((m = paramRegex.exec(paramsStr)) !== null) {
                const k = m[1];
                const rawVal = m[2].trim();
                if ((rawVal.startsWith("'") && rawVal.endsWith("'")) || (rawVal.startsWith('"') && rawVal.endsWith('"'))) {
                    params[k] = rawVal.slice(1, -1);
                } else {
                    params[k] = getValueFromScope(rawVal, scope);
                }
            }
        }
        return resolveUrl(route, params);
    }

    // Check for .get(key, default) e.g. log['data'].get(field['field_label'], 'N/A')
    const getMatch = trimmed.match(/^([\w.\[\]'"]+)\.get\s*\(\s*(['"][^'"]*['"]|[\w.\[\]'"]+)(?:\s*,\s*(['"][^'"]*['"]|[\w.\[\]'"]+))?\s*\)$/);
    if (getMatch) {
        const obj = getValueFromScope(getMatch[1], scope);
        const key = getValueFromScope(getMatch[2], scope);
        let defaultVal = getMatch[3] ? getValueFromScope(getMatch[3], scope) : '';
        if (obj && typeof obj === 'object') {
            const val = obj[key];
            return (val !== undefined && val !== null) ? val : defaultVal;
        }
        return defaultVal;
    }

    // Check for Python ternary: expr if cond else expr
    const ternaryMatch = trimmed.match(/^(.+?)\s+if\s+(.+?)\s+else\s+(.+)$/);
    if (ternaryMatch) {
        const cond = evaluateCondition(ternaryMatch[2], scope);
        return cond ? getValueFromScope(ternaryMatch[1], scope) : getValueFromScope(ternaryMatch[3], scope);
    }

    // Handle method calls
    let expr = trimmed;
    let callUpper = false;
    let callLower = false;
    if (expr.endsWith('.upper()') || expr.endsWith('.toUpperCase()')) {
        callUpper = true;
        expr = expr.replace(/\.(upper|toUpperCase)\(\)$/, '');
    } else if (expr.endsWith('.lower()') || expr.endsWith('.toLowerCase()')) {
        callLower = true;
        expr = expr.replace(/\.(lower|toLowerCase)\(\)$/, '');
    }

    // Normalize brackets: a['b'][0] -> a.b.0
    const normalized = expr
        .replace(/\[['"](.*?)['"]\]/g, '.$1')
        .replace(/\[(\d+)\]/g, '.$1');

    const parts = normalized.split('.');
    let curr = scope;
    for (const p of parts) {
        if (curr === undefined || curr === null) {
            curr = undefined;
            break;
        }
        curr = curr[p];
    }

    if (curr !== undefined && curr !== null) {
        if (callUpper) return String(curr).toUpperCase();
        if (callLower) return String(curr).toLowerCase();
    }
    return curr;
}

function evaluateCondition(condStr, scope) {
    const trimmed = condStr.trim();
    if (!trimmed) return false;

    if (trimmed.startsWith('not ')) {
        return !evaluateCondition(trimmed.slice(4), scope);
    }

    if (trimmed.includes(' and ')) {
        const parts = trimmed.split(' and ');
        return parts.every(p => evaluateCondition(p, scope));
    }

    if (trimmed.includes(' or ')) {
        const parts = trimmed.split(' or ');
        return parts.some(p => evaluateCondition(p, scope));
    }

    if (trimmed.includes(' == ')) {
        const [l, r] = trimmed.split(' == ');
        return getValueFromScope(l, scope) == getValueFromScope(r, scope);
    }

    if (trimmed.includes(' != ')) {
        const [l, r] = trimmed.split(' != ');
        return getValueFromScope(l, scope) != getValueFromScope(r, scope);
    }

    const val = getValueFromScope(trimmed, scope);
    if (Array.isArray(val)) return val.length > 0;
    return !!val;
}

function renderExpression(expr, scope) {
    expr = expr.trim();
    if (!expr) return '';

    // Check filters: expr | filter
    if (expr.includes('|')) {
        const pipeIdx = expr.indexOf('|');
        const mainExpr = expr.slice(0, pipeIdx).trim();
        const filterExpr = expr.slice(pipeIdx + 1).trim();
        const val = getValueFromScope(mainExpr, scope);

        if (filterExpr.startsWith('tojson')) {
            return JSON.stringify(val ?? null);
        }
        if (filterExpr.startsWith('safe')) {
            return val !== undefined ? String(val) : '';
        }
        if (filterExpr.startsWith('length')) {
            let len = Array.isArray(val) ? val.length : (typeof val === 'string' ? val.length : 0);
            const mathMatch = filterExpr.match(/length\s*([+\-*/])\s*(\d+)/);
            if (mathMatch) {
                const op = mathMatch[1];
                const num = parseInt(mathMatch[2]);
                if (op === '+') len += num;
                else if (op === '-') len -= num;
                else if (op === '*') len *= num;
            }
            return String(len);
        }
        if (filterExpr.startsWith('timestamp_format')) {
            if (!val) return '';
            try {
                const d = new Date(val);
                return d.toLocaleString('en-US', {
                    month: 'short', day: 'numeric', year: 'numeric',
                    hour: '2-digit', minute: '2-digit', hour12: true
                });
            } catch {
                return String(val);
            }
        }
        return escapeHtml(val);
    }

    // Handle url_for(...)
    const urlForMatch = expr.match(/^url_for\s*\(\s*['"]([^'"]+)['"](?:\s*,\s*([\s\S]+))?\s*\)$/);
    if (urlForMatch) {
        const route = urlForMatch[1];
        const paramsStr = urlForMatch[2];
        const params = {};
        if (paramsStr) {
            const paramRegex = /(\w+)\s*=\s*(['"][^'"]*['"]|[^,]+)/g;
            let m;
            while ((m = paramRegex.exec(paramsStr)) !== null) {
                const k = m[1];
                const rawVal = m[2].trim();
                if ((rawVal.startsWith("'") && rawVal.endsWith("'")) || (rawVal.startsWith('"') && rawVal.endsWith('"'))) {
                    params[k] = rawVal.slice(1, -1);
                } else {
                    params[k] = getValueFromScope(rawVal, scope);
                }
            }
        }
        return resolveUrl(route, params);
    }

    const val = getValueFromScope(expr, scope);
    return val !== undefined ? escapeHtml(val) : '';
}

function render(templateName, context = {}) {
    let template = TEMPLATES[templateName] || '';

    // Strip comments {# ... #}
    template = template.replace(/\{#[\s\S]*?#\}/g, '');

    // Resolve includes
    let hasIncludes = true;
    let incDepth = 0;
    while (hasIncludes && incDepth < 10) {
        incDepth++;
        hasIncludes = false;
        template = template.replace(/\{%\s*include\s+['"]([^'"]+)['"]\s*%\}/g, (m, inc) => {
            hasIncludes = true;
            const name = inc.replace('.html', '');
            let incTmpl = TEMPLATES[name] || '';
            return incTmpl.replace(/\{#[\s\S]*?#\}/g, '');
        });
    }

    // Handle extends
    const extendsMatch = template.match(/\{%\s*extends\s+['"]([^'"]+)['"]\s*%\}/);
    if (extendsMatch) {
        let layout = TEMPLATES['layout'] || '';
        const blocks = {};
        const blockRegex = /\{%\s*block\s+(\w+)\s*%\}([\s\S]*?)\{%\s*endblock\s*%\}/g;
        let m;
        while ((m = blockRegex.exec(template)) !== null) {
            blocks[m[1]] = m[2];
        }

        template = layout.replace(/\{%\s*block\s+(\w+)\s*%\}[\s\S]*?\{%\s*endblock\s*%\}/g, (match, bName) => {
            return blocks[bName] !== undefined ? blocks[bName] : '';
        });

        // Re-resolve any includes inside blocks
        template = template.replace(/\{%\s*include\s+['"]([^'"]+)['"]\s*%\}/g, (m2, inc) => {
            const name = inc.replace('.html', '');
            let incTmpl = TEMPLATES[name] || '';
            return incTmpl.replace(/\{#[\s\S]*?#\}/g, '');
        });
        template = template.replace(/\{#[\s\S]*?#\}/g, '');
    }

    // Render parsed AST / stream
    let pos = 0;

    function renderStream(scope, endTags = []) {
        let out = '';

        while (pos < template.length) {
            const nextTag = template.indexOf('{', pos);
            if (nextTag === -1) {
                out += template.slice(pos);
                pos = template.length;
                break;
            }

            out += template.slice(pos, nextTag);
            pos = nextTag;

            if (template[pos + 1] === '%') {
                const closeIdx = template.indexOf('%}', pos);
                if (closeIdx === -1) {
                    out += template.slice(pos);
                    pos = template.length;
                    break;
                }
                const fullTag = template.slice(pos + 2, closeIdx).trim();
                const tagParts = fullTag.split(/\s+/);
                const tagName = tagParts[0];
                pos = closeIdx + 2;

                if (endTags.includes(tagName)) {
                    return { output: out, closedBy: tagName, tagContent: fullTag };
                }

                if (tagName === 'for') {
                    // {% for item in list %}
                    const forMatch = fullTag.match(/^for\s+([\w, ]+)\s+in\s+([\w.\[\]'"]+)/);
                    const loopVar = forMatch ? forMatch[1].trim() : '';
                    const listExpr = forMatch ? forMatch[2].trim() : '';
                    const listVal = getValueFromScope(listExpr, scope) || [];

                    const loopBodyStart = pos;
                    let aggregatedBody = '';

                    if (Array.isArray(listVal) && listVal.length > 0) {
                        for (let i = 0; i < listVal.length; i++) {
                            pos = loopBodyStart;
                            const item = listVal[i];
                            let innerScope = { ...scope, loop: { index: i + 1, index0: i, first: i === 0, last: i === listVal.length - 1 } };
                            
                            if (loopVar.includes(',')) {
                                const parts = loopVar.split(',').map(s => s.trim());
                                if (Array.isArray(item)) {
                                    innerScope[parts[0]] = item[0];
                                    innerScope[parts[1]] = item[1];
                                } else if (item && typeof item === 'object') {
                                    innerScope[parts[0]] = item.category || Object.keys(item)[0];
                                    innerScope[parts[1]] = item.message || Object.values(item)[0];
                                }
                            } else {
                                innerScope[loopVar] = item;
                            }

                            const rendered = renderStream(innerScope, ['endfor']);
                            aggregatedBody += rendered.output;
                        }
                    } else {
                        // Skip loop body
                        renderStream(scope, ['endfor']);
                    }
                    out += aggregatedBody;
                } else if (tagName === 'if') {
                    const condExpr = fullTag.slice(2).trim();
                    const condPassed = evaluateCondition(condExpr, scope);

                    let branch = renderStream(scope, ['else', 'elif', 'endif']);
                    if (condPassed) {
                        out += branch.output;
                    }

                    let handled = condPassed;
                    while (branch.closedBy === 'elif') {
                        const elifCond = branch.tagContent.slice(4).trim();
                        const elifPassed = !handled && evaluateCondition(elifCond, scope);
                        const nextBranch = renderStream(scope, ['else', 'elif', 'endif']);
                        if (elifPassed) {
                            out += nextBranch.output;
                            handled = true;
                        }
                        branch = nextBranch;
                    }

                    if (branch.closedBy === 'else') {
                        const elseBranch = renderStream(scope, ['endif']);
                        if (!handled) {
                            out += elseBranch.output;
                        }
                    }
                } else if (tagName === 'with') {
                    const withMatch = fullTag.match(/^with\s+(\w+)\s*=\s*(.+)$/);
                    let innerScope = { ...scope };
                    if (withMatch) {
                        const varName = withMatch[1];
                        const varExpr = withMatch[2];
                        if (varExpr.startsWith('get_flashed_messages')) {
                            innerScope[varName] = scope.flash_messages || [];
                        } else {
                            innerScope[varName] = getValueFromScope(varExpr, scope);
                        }
                    }
                    const withBranch = renderStream(innerScope, ['endwith']);
                    out += withBranch.output;
                } else if (tagName === 'set') {
                    const setMatch = fullTag.match(/^set\s+(\w+)\s*=\s*(.+)$/);
                    if (setMatch) {
                        scope[setMatch[1]] = getValueFromScope(setMatch[2], scope);
                    }
                }
            } else if (template[pos + 1] === '{') {
                const closeIdx = template.indexOf('}}', pos);
                if (closeIdx === -1) {
                    out += template.slice(pos);
                    pos = template.length;
                    break;
                }
                const expr = template.slice(pos + 2, closeIdx).trim();
                pos = closeIdx + 2;
                out += renderExpression(expr, scope);
            } else {
                out += template[pos];
                pos++;
            }
        }

        return { output: out, closedBy: null };
    }

    return renderStream(context, []).output;
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

function getBaseUrl(c) {
    if (c.env.BASE_URL && !c.env.BASE_URL.includes('workers.dev')) {
        return c.env.BASE_URL;
    }
    const url = new URL(c.req.url);
    if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
        return `${url.protocol}//${url.host}`;
    }
    return c.env.BASE_URL || `${url.protocol}//${url.host}`;
}

// ============================
// DATABASE & CONNECTION CACHE
// ============================

let cachedSql = null;
let lastDbUrl = null;

function getSql(c) {
    const dbUrl = c.env.DATABASE_URL;
    if (!dbUrl) return null;
    if (cachedSql && lastDbUrl === dbUrl) return cachedSql;
    cachedSql = neon(dbUrl);
    lastDbUrl = dbUrl;
    return cachedSql;
}

function getDb(c) {
    const dbUrl = c.env.DATABASE_URL;
    if (dbUrl) {
        const sql = getSql(c);
        return {
            prepare(query) {
                const makeStatement = (params = []) => ({
                    async first() {
                        let pIndex = 1;
                        const pgQuery = query.replace(/\?/g, () => `$${pIndex++}`);
                        const rows = await sql.query(pgQuery, params);
                        return rows && rows[0] ? rows[0] : null;
                    },
                    async all() {
                        let pIndex = 1;
                        const pgQuery = query.replace(/\?/g, () => `$${pIndex++}`);
                        const rows = await sql.query(pgQuery, params);
                        return { results: rows || [] };
                    },
                    async run() {
                        let pIndex = 1;
                        const pgQuery = query.replace(/\?/g, () => `$${pIndex++}`);
                        await sql.query(pgQuery, params);
                        return { success: true };
                    }
                });

                return {
                    ...makeStatement([]),
                    bind(...params) {
                        return makeStatement(params);
                    }
                };
            }
        };
    }
    return c.env.DB;
}

// ============================
// ULTRA-FAST IN-MEMORY CACHE
// ============================

const MEMORY_CACHE = {
    users: new Map(),       // username -> { user, time }
    dashboard: null,        // { pending_staff, approved_staff, all_events, time }
    staffEvents: new Map(), // username -> { data, time }
    eventStaff: new Map(),  // eventId -> { data, time }
    eventFields: new Map(), // eventId -> { data, time }
};

const CACHE_TTL = 30000; // 30 seconds

function invalidateAllCaches() {
    MEMORY_CACHE.dashboard = null;
    MEMORY_CACHE.staffEvents.clear();
    MEMORY_CACHE.eventStaff.clear();
    MEMORY_CACHE.eventFields.clear();
}

async function getUser(db, username) {
    const cached = MEMORY_CACHE.users.get(username);
    if (cached && (Date.now() - cached.time < CACHE_TTL)) {
        return cached.user;
    }
    const u = await db.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
    if (u) {
        u.initial = u.name ? u.name.charAt(0).toUpperCase() : (u.role === 'superadmin' ? 'A' : 'S');
        MEMORY_CACHE.users.set(username, { user: u, time: Date.now() });
    }
    return u;
}

// ============================
// ENTERPRISE SAAS CSS STYLES
// ============================

const styleCss = `:root{--bg-dark:#090d16;--bg-card:rgba(15,23,42,0.75);--border-card:rgba(255,255,255,0.08);--primary:#3b82f6;--primary-hover:#2563eb;--emerald:#10b981;--emerald-hover:#059669;--danger:#ef4444;--amber:#f59e0b}*{-webkit-tap-highlight-color:transparent;box-sizing:border-box}html,body{height:100%}body{font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#e2e8f0;background-color:#090d16;background-image:radial-gradient(at 0% 0%,rgba(37,99,235,0.1) 0px,transparent 50%),radial-gradient(at 100% 100%,rgba(99,102,241,0.08) 0px,transparent 50%),radial-gradient(at 50% 50%,rgba(15,23,42,0.4) 0px,transparent 100%);background-attachment:fixed;min-height:100%;margin:0;-webkit-font-smoothing:antialiased}.card{background-color:var(--bg-card);border:1px solid var(--border-card);border-radius:1rem;backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);box-shadow:0 10px 30px -5px rgba(0,0,0,0.5),0 0 0 1px rgba(255,255,255,0.05);transition:border-color .2s ease,box-shadow .2s ease}.card:hover{border-color:rgba(59,130,246,0.4);box-shadow:0 14px 35px -5px rgba(0,0,0,0.6),0 0 15px -3px rgba(59,130,246,0.15)}.form-input{background-color:rgba(15,23,42,0.6);border:1px solid rgba(255,255,255,0.12);color:#f8fafc;border-radius:.625rem;transition:all .2s ease;font-size:15px}.form-input:focus{outline:none;border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,0.25);background-color:rgba(15,23,42,0.9)}.form-input::placeholder{color:#64748b}.btn{position:relative;padding:.625rem 1.25rem;border-radius:.625rem;font-weight:600;font-size:.875rem;color:#fff;text-align:center;transition:all .2s ease;border:none;cursor:pointer;min-height:42px;display:inline-flex;align-items:center;justify-content:center;gap:.5rem;text-decoration:none}.btn:hover{transform:translateY(-1px);box-shadow:0 4px 12px rgba(0,0,0,0.3)}.btn:active{transform:translateY(0)}.btn-primary{background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%);box-shadow:0 2px 10px rgba(37,99,235,0.3)}.btn-primary:hover{background:linear-gradient(135deg,#60a5fa 0%,#3b82f6 100%);box-shadow:0 4px 16px rgba(37,99,235,0.45)}.btn-emerald{background:linear-gradient(135deg,#10b981 0%,#059669 100%);box-shadow:0 2px 10px rgba(16,185,129,0.3);color:#fff}.btn-emerald:hover{background:linear-gradient(135deg,#34d399 0%,#10b981 100%);box-shadow:0 4px 16px rgba(16,185,129,0.45)}.btn-danger{background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%)}.btn-warning{background:linear-gradient(135deg,#f59e0b 0%,#d97706 100%)}.btn-purple{background:linear-gradient(135deg,#8b5cf6 0%,#7c3aed 100%)}.btn-outline{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.15);color:#e2e8f0}.btn-outline:hover{background:rgba(255,255,255,0.1);border-color:rgba(255,255,255,0.25)}.ticket-container{background:linear-gradient(145deg,#131b2e 0%,#0f172a 100%);border:1px solid rgba(255,255,255,0.12);border-radius:1.25rem;position:relative;box-shadow:0 20px 40px -10px rgba(0,0,0,0.7);overflow:hidden}.ticket-notch-left,.ticket-notch-right{position:absolute;width:24px;height:24px;background:#090d16;border-radius:50%;z-index:20;top:45%}.ticket-notch-left{left:-12px}.ticket-notch-right{right:-12px}.ticket-perforation{border-bottom:2px dashed rgba(255,255,255,0.15)}@keyframes scanLaser{0%{top:5%;opacity:.8}50%{top:90%;opacity:1}100%{top:5%;opacity:.8}}.scanner-laser{position:absolute;left:5%;width:90%;height:3px;background:linear-gradient(90deg,transparent,#3b82f6,#60a5fa,#3b82f6,transparent);box-shadow:0 0 12px #3b82f6,0 0 4px #60a5fa;animation:scanLaser 2.2s ease-in-out infinite;pointer-events:none;z-index:10}.badge-checked{background:rgba(16,185,129,0.15);color:#34d399;border:1px solid rgba(16,185,129,0.3)}.badge-pending{background:rgba(100,116,139,0.15);color:#94a3b8;border:1px solid rgba(100,116,139,0.25)}.badge-alert{background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.3)}@media print{body{background:#fff!important;color:#000!important}header,#spa-progress-bar,.no-print{display:none!important}.ticket-container{box-shadow:none!important;border:2px solid #000!important;background:#fff!important;color:#000!important}}`;

// ============================
// ROUTES
// ============================

// Static CSS
app.get('/static/css/style.css', (c) => {
    return new Response(styleCss, {
        headers: {
            'Content-Type': 'text/css',
            'Cache-Control': 'public, max-age=31536000'
        }
    });
});

// Login
const handleLoginGet = async (c) => {
    const session = getSession(c);
    if (session.username) {
        return c.redirect(session.role === 'superadmin' ? '/superadmin' : '/staff/events');
    }
    return c.html(render('login', { user: null, flash_messages: [], request: { path: '/' } }));
};

const handleLoginPost = async (c) => {
    const body = await c.req.parseBody();
    const db = getDb(c);
    const user = await getUser(db, body.username);

    if (user && user.password === body.password) {
        if (user.approved === 0) {
            return c.html(render('pending', { request: { path: '/pending' } }));
        }
        setSession(c, { username: user.username, role: user.role, name: user.name });
        return c.redirect(user.role === 'superadmin' ? '/superadmin' : '/staff/events');
    }
    return c.html(render('login', { user: null, flash_messages: [{ category: 'error', message: 'Invalid credentials.' }], request: { path: '/' } }));
};

app.get('/', handleLoginGet);
app.get('/login', handleLoginGet);
app.post('/', handleLoginPost);
app.post('/login', handleLoginPost);

// Register
app.get('/register', (c) => c.html(render('register', { user: null, flash_messages: [], request: { path: '/register' } })));

app.post('/register', async (c) => {
    const body = await c.req.parseBody();
    const db = getDb(c);

    const existing = await getUser(db, body.username);
    if (existing) {
        return c.html(render('register', { user: null, flash_messages: [{ category: 'error', message: 'Username already taken.' }], request: { path: '/register' } }));
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

    const db = getDb(c);
    const user = await getUser(db, session.username);

    let data = MEMORY_CACHE.dashboard;
    if (!data || (Date.now() - data.time > CACHE_TTL)) {
        const sql = getSql(c);
        if (sql) {
            const rows = await sql`
                SELECT 
                    (SELECT json_agg(u) FROM (SELECT * FROM users WHERE role != 'superadmin' AND approved = 0) u) as pending_staff,
                    (SELECT json_agg(u) FROM (SELECT * FROM users WHERE role != 'superadmin' AND approved = 1) u) as approved_staff,
                    (SELECT json_agg(e) FROM (
                        SELECT e.*, 
                            COALESCE(ea.cnt, 0) as staff_count,
                            COALESCE(lc.total_regs, 0) as registered_count,
                            COALESCE(lc.checked_cnt, 0) as checked_in_count
                        FROM events e 
                        LEFT JOIN (SELECT event_id, COUNT(*) as cnt FROM event_admins GROUP BY event_id) ea 
                            ON e.event_id = ea.event_id
                        LEFT JOIN (
                            SELECT event_id, 
                                COUNT(*) as total_regs, 
                                COUNT(CASE WHEN status = 'checked_in' THEN 1 END) as checked_cnt 
                            FROM logs GROUP BY event_id
                        ) lc ON e.event_id = lc.event_id
                        ORDER BY e.event_id DESC
                    ) e) as all_events;
            `;
            const r = rows && rows[0] ? rows[0] : {};
            data = {
                pending_staff: r.pending_staff || [],
                approved_staff: r.approved_staff || [],
                all_events: r.all_events || [],
                time: Date.now()
            };
        } else {
            const [pendingRes, approvedRes, eventsRes] = await Promise.all([
                db.prepare("SELECT * FROM users WHERE role != 'superadmin' AND approved = 0").all(),
                db.prepare("SELECT * FROM users WHERE role != 'superadmin' AND approved = 1").all(),
                db.prepare("SELECT e.*, COUNT(ea.id) as staff_count FROM events e LEFT JOIN event_admins ea ON e.event_id = ea.event_id GROUP BY e.event_id").all()
            ]);
            data = {
                pending_staff: pendingRes.results || [],
                approved_staff: approvedRes.results || [],
                all_events: eventsRes.results || [],
                time: Date.now()
            };
        }
        MEMORY_CACHE.dashboard = data;
    }

    const pending_staff = data.pending_staff.map(s => ({
        ...s,
        initial: s.name ? s.name.charAt(0).toUpperCase() : 'S'
    }));

    const approved_staff = data.approved_staff.map(s => ({
        ...s,
        initial: s.name ? s.name.charAt(0).toUpperCase() : 'S'
    }));

    // Calculate executive KPIs
    const totalEvents = data.all_events.length;
    const totalRegistrations = data.all_events.reduce((sum, e) => sum + parseInt(e.registered_count || 0, 10), 0);
    const totalCheckedIn = data.all_events.reduce((sum, e) => sum + parseInt(e.checked_in_count || 0, 10), 0);
    const activeStaffCount = approved_staff.length;

    return c.html(render('superadmin/dashboard', {
        user,
        pending_staff,
        approved_staff,
        all_events: data.all_events,
        totalEvents,
        totalRegistrations,
        totalCheckedIn,
        activeStaffCount,
        flash_messages: [],
        request: { path: '/superadmin' }
    }));
});

// Superadmin - Create Event
app.post('/superadmin/event/create', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');
    const body = await c.req.parseBody();
    const db = getDb(c);
    const capacity = parseInt(body.capacity || '100', 10);
    const eventDate = body.event_date || '';
    const venue = body.venue || '';
    const description = body.description || '';

    const newEvent = await db.prepare("INSERT INTO events (event_name, capacity, event_date, venue, description) VALUES (?, ?, ?, ?, ?) RETURNING event_id")
        .bind(body.event_name, capacity, eventDate, venue, description).first();

    const newId = newEvent?.event_id;
    if (newId) {
        // Auto-seed standard attendee registration fields so the event is immediately ready to use!
        await db.prepare("INSERT INTO event_fields (event_id, field_label, field_type, is_required, field_order) VALUES (?, 'Full Name', 'text', 1, 1)").bind(newId).run();
        await db.prepare("INSERT INTO event_fields (event_id, field_label, field_type, is_required, field_order) VALUES (?, 'Email Address', 'email', 1, 2)").bind(newId).run();
        await db.prepare("INSERT INTO event_fields (event_id, field_label, field_type, is_required, field_order) VALUES (?, 'Student ID / Roll No', 'text', 1, 3)").bind(newId).run();
        await db.prepare("INSERT INTO event_fields (event_id, field_label, field_type, is_required, field_order) VALUES (?, 'Phone Number', 'tel', 0, 4)").bind(newId).run();
    }

    invalidateAllCaches();
    return c.redirect('/superadmin');
});

// Superadmin - Approve Staff
app.post('/superadmin/approve/:username', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');
    const db = getDb(c);
    const username = c.req.param('username');
    await db.prepare("UPDATE users SET approved = 1 WHERE username = ?").bind(username).run();
    MEMORY_CACHE.users.delete(username);
    invalidateAllCaches();
    return c.redirect('/superadmin');
});

// Superadmin - Delete Staff
app.post('/superadmin/delete/:username', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');
    const db = getDb(c);
    const username = c.req.param('username');
    await db.prepare("DELETE FROM users WHERE username = ?").bind(username).run();
    await db.prepare("DELETE FROM event_admins WHERE admin_username = ?").bind(username).run();
    MEMORY_CACHE.users.delete(username);
    invalidateAllCaches();
    return c.redirect('/superadmin');
});

// Superadmin - Delete Event
app.post('/superadmin/event/delete/:event_id', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');
    const eventId = c.req.param('event_id');
    const db = getDb(c);
    await db.prepare("DELETE FROM events WHERE event_id = ?").bind(eventId).run();
    await db.prepare("DELETE FROM event_fields WHERE event_id = ?").bind(eventId).run();
    await db.prepare("DELETE FROM event_admins WHERE event_id = ?").bind(eventId).run();
    await db.prepare("DELETE FROM logs WHERE event_id = ?").bind(eventId).run();
    invalidateAllCaches();
    return c.redirect('/superadmin');
});

// Superadmin - Manage Event Staff
app.get('/superadmin/event/staff/:event_id', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');
    const eventId = parseInt(c.req.param('event_id'), 10);
    const db = getDb(c);
    const user = await getUser(db, session.username);

    let data = MEMORY_CACHE.eventStaff.get(eventId);
    if (!data || (Date.now() - data.time > CACHE_TTL)) {
        const sql = getSql(c);
        if (sql) {
            const rows = await sql`
                SELECT 
                    (SELECT row_to_json(e) FROM events e WHERE e.event_id = ${eventId}) as event,
                    (SELECT json_agg(u) FROM (SELECT u.* FROM users u JOIN event_admins ea ON u.username = ea.admin_username WHERE ea.event_id = ${eventId}) u) as assigned_staff,
                    (SELECT json_agg(u) FROM (SELECT * FROM users WHERE role != 'superadmin' AND approved = 1 AND username NOT IN (SELECT admin_username FROM event_admins WHERE event_id = ${eventId})) u) as unassigned_staff;
            `;
            const r = rows && rows[0] ? rows[0] : {};
            if (!r.event) return c.redirect('/superadmin');
            data = {
                event: r.event,
                assigned_staff: r.assigned_staff || [],
                unassigned_staff: r.unassigned_staff || [],
                time: Date.now()
            };
        } else {
            const [event, assignedRes, unassignedRes] = await Promise.all([
                db.prepare("SELECT * FROM events WHERE event_id = ?").bind(eventId).first(),
                db.prepare("SELECT u.* FROM users u JOIN event_admins ea ON u.username = ea.admin_username WHERE ea.event_id = ?").bind(eventId).all(),
                db.prepare("SELECT * FROM users WHERE role != 'superadmin' AND approved = 1 AND username NOT IN (SELECT admin_username FROM event_admins WHERE event_id = ?)").bind(eventId).all()
            ]);
            if (!event) return c.redirect('/superadmin');
            data = {
                event,
                assigned_staff: assignedRes.results || [],
                unassigned_staff: unassignedRes.results || [],
                time: Date.now()
            };
        }
        MEMORY_CACHE.eventStaff.set(eventId, data);
    }

    return c.html(render('superadmin/manage_staff', {
        user,
        event: data.event,
        assigned_staff: data.assigned_staff,
        unassigned_staff: data.unassigned_staff,
        flash_messages: [],
        request: { path: `/superadmin/event/staff/${eventId}` }
    }));
});

// Superadmin - Add Staff to Event
app.post('/superadmin/event/staff/add/:event_id/:username', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');
    const db = getDb(c);
    const eventId = c.req.param('event_id');
    await db.prepare("INSERT INTO event_admins (event_id, admin_username) VALUES (?, ?)").bind(eventId, c.req.param('username')).run();
    invalidateAllCaches();
    return c.redirect(`/superadmin/event/staff/${eventId}`);
});

// Superadmin - Remove Staff from Event
app.post('/superadmin/event/staff/remove/:event_id/:username', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');
    const db = getDb(c);
    const eventId = c.req.param('event_id');
    await db.prepare("DELETE FROM event_admins WHERE event_id = ? AND admin_username = ?").bind(eventId, c.req.param('username')).run();
    invalidateAllCaches();
    return c.redirect(`/superadmin/event/staff/${eventId}`);
});

// Superadmin - Edit Event Form
app.get('/superadmin/event/edit/:event_id', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');
    const eventId = parseInt(c.req.param('event_id'), 10);
    const db = getDb(c);
    const user = await getUser(db, session.username);

    let data = MEMORY_CACHE.eventFields.get(eventId);
    if (!data || (Date.now() - data.time > CACHE_TTL)) {
        const sql = getSql(c);
        if (sql) {
            const rows = await sql`
                SELECT 
                    (SELECT row_to_json(e) FROM events e WHERE e.event_id = ${eventId}) as event,
                    (SELECT json_agg(f) FROM (SELECT * FROM event_fields WHERE event_id = ${eventId} ORDER BY field_order ASC, field_id ASC) f) as fields;
            `;
            const r = rows && rows[0] ? rows[0] : {};
            if (!r.event) return c.redirect('/superadmin');
            data = {
                event: r.event,
                fields: r.fields || [],
                time: Date.now()
            };
        } else {
            const [event, fieldsRes] = await Promise.all([
                db.prepare("SELECT * FROM events WHERE event_id = ?").bind(eventId).first(),
                db.prepare("SELECT * FROM event_fields WHERE event_id = ? ORDER BY field_order ASC, field_id ASC").bind(eventId).all()
            ]);
            if (!event) return c.redirect('/superadmin');
            data = {
                event,
                fields: fieldsRes.results || [],
                time: Date.now()
            };
        }
        MEMORY_CACHE.eventFields.set(eventId, data);
    }

    return c.html(render('superadmin/edit_form', {
        user,
        event: data.event,
        fields: data.fields,
        flash_messages: [],
        request: { path: `/superadmin/event/edit/${eventId}` }
    }));
});

app.post('/superadmin/event/edit/:event_id', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');
    const eventId = c.req.param('event_id');
    const body = await c.req.parseBody();
    const db = getDb(c);
    const isRequired = body.is_required ? 1 : 0;
    await db.prepare("INSERT INTO event_fields (event_id, field_label, field_type, is_required) VALUES (?, ?, ?, ?)")
        .bind(eventId, body.field_label, body.field_type, isRequired).run();
    invalidateAllCaches();
    return c.redirect(`/superadmin/event/edit/${eventId}`);
});

// Superadmin - Delete Field
app.post('/superadmin/field/delete/:field_id', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');
    const db = getDb(c);
    const field = await db.prepare("SELECT event_id FROM event_fields WHERE field_id = ?").bind(c.req.param('field_id')).first();
    if (field) {
        await db.prepare("DELETE FROM event_fields WHERE field_id = ?").bind(c.req.param('field_id')).run();
        invalidateAllCaches();
        return c.redirect(`/superadmin/event/edit/${field.event_id}`);
    }
    return c.redirect('/superadmin');
});

// Superadmin Profile
app.get('/superadmin/profile', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');
    const db = getDb(c);
    const user = await getUser(db, session.username);
    return c.html(render('superadmin/profile', {
        user,
        flash_messages: [],
        request: { path: '/superadmin/profile' }
    }));
});

app.post('/superadmin/update', async (c) => {
    const session = getSession(c);
    if (session.role !== 'superadmin') return c.redirect('/');
    const body = await c.req.parseBody();
    const db = getDb(c);
    if (body.password) {
        await db.prepare("UPDATE users SET password = ? WHERE username = ?").bind(body.password, session.username).run();
    }
    return c.redirect('/superadmin/profile');
});

// Staff Events
app.get('/staff/events', async (c) => {
    const session = getSession(c);
    if (!session.username) return c.redirect('/');
    const db = getDb(c);
    const user = await getUser(db, session.username);

    let events = MEMORY_CACHE.staffEvents.get(session.username);
    if (!events || (Date.now() - events.time > CACHE_TTL)) {
        const sql = getSql(c);
        let rawEvents = [];
        if (sql) {
            rawEvents = await sql`SELECT e.* FROM events e JOIN event_admins ea ON e.event_id = ea.event_id WHERE ea.admin_username = ${session.username}`;
        } else {
            const result = await db.prepare("SELECT e.* FROM events e JOIN event_admins ea ON e.event_id = ea.event_id WHERE ea.admin_username = ?").bind(session.username).all();
            rawEvents = result.results || [];
        }
        const baseUrl = getBaseUrl(c);
        events = {
            data: rawEvents.map(e => ({ ...e, url: `${baseUrl}/attend/${e.event_id}` })),
            time: Date.now()
        };
        MEMORY_CACHE.staffEvents.set(session.username, events);
    }

    return c.html(render('staff/events', {
        user,
        events: events.data,
        flash_messages: [],
        request: { path: '/staff/events' }
    }));
});

// Staff Profile
app.get('/staff/profile', async (c) => {
    const session = getSession(c);
    if (!session.username) return c.redirect('/');
    const db = getDb(c);
    const user = await getUser(db, session.username);
    return c.html(render('staff/profile', {
        user,
        flash_messages: [],
        request: { path: '/staff/profile' }
    }));
});

app.post('/staff/update', async (c) => {
    const session = getSession(c);
    if (!session.username) return c.redirect('/');
    const body = await c.req.parseBody();
    const db = getDb(c);
    let query = "UPDATE users SET name = ?, phone = ?, address = ?";
    const params = [body.name, body.phone, body.address];
    if (body.password) { query += ", password = ?"; params.push(body.password); }
    query += " WHERE username = ?";
    params.push(session.username);
    await db.prepare(query).bind(...params).run();
    MEMORY_CACHE.users.delete(session.username);
    invalidateAllCaches();
    return c.redirect('/staff/profile');
});

// Staff - View Logs
app.get('/staff/event/:event_id/logs', async (c) => {
    const session = getSession(c);
    if (!session.username) return c.redirect('/');
    const eventId = parseInt(c.req.param('event_id'), 10);
    const db = getDb(c);
    const user = await getUser(db, session.username);

    const sql = getSql(c);
    let event, fields, logsRaw, log_count;

    if (sql) {
        const rows = await sql`
            SELECT 
                (SELECT row_to_json(e) FROM events e WHERE e.event_id = ${eventId}) as event,
                (SELECT json_agg(f) FROM (SELECT * FROM event_fields WHERE event_id = ${eventId} ORDER BY field_order ASC, field_id ASC) f) as fields,
                (SELECT json_agg(l) FROM (SELECT * FROM logs WHERE event_id = ${eventId} ORDER BY log_id DESC LIMIT 50) l) as logs,
                (SELECT COUNT(*) FROM logs WHERE event_id = ${eventId}) as count;
        `;
        const r = rows && rows[0] ? rows[0] : {};
        event = r.event;
        fields = r.fields || [];
        logsRaw = r.logs || [];
        log_count = parseInt(r.count || '0', 10);
    } else {
        const [eventRes, fieldsRes, logsRawRes, countResult] = await Promise.all([
            db.prepare("SELECT * FROM events WHERE event_id = ?").bind(eventId).first(),
            db.prepare("SELECT * FROM event_fields WHERE event_id = ? ORDER BY field_order ASC, field_id ASC").bind(eventId).all(),
            db.prepare("SELECT * FROM logs WHERE event_id = ? ORDER BY log_id DESC LIMIT 50").bind(eventId).all(),
            db.prepare("SELECT COUNT(*) as count FROM logs WHERE event_id = ?").bind(eventId).first()
        ]);
        event = eventRes;
        fields = fieldsRes.results || [];
        logsRaw = logsRawRes.results || [];
        log_count = parseInt(countResult?.count || '0', 10);
    }

    if (!event) return c.redirect('/superadmin');

    if (session.role !== 'superadmin') {
        const access = await db.prepare("SELECT 1 FROM event_admins WHERE event_id = ? AND admin_username = ?").bind(eventId, session.username).first();
        if (!access) return c.redirect('/staff/events');
    }

    const logs = logsRaw.map(l => {
        let dataObj = {};
        if (typeof l.data === 'object' && l.data !== null) {
            dataObj = l.data;
        } else {
            try { dataObj = JSON.parse(l.data); } catch { dataObj = {}; }
        }
        return {
            ...l,
            data: dataObj
        };
    });

    return c.html(render('staff/logs', {
        user,
        event,
        fields,
        logs,
        log_count,
        flash_messages: [],
        request: { path: `/staff/event/${eventId}/logs` }
    }));
});

// Staff - Delete Log
app.post('/staff/log/delete/:log_id/:event_id', async (c) => {
    const session = getSession(c);
    if (!session.username) return c.redirect('/');
    const db = getDb(c);
    await db.prepare("DELETE FROM logs WHERE log_id = ?").bind(c.req.param('log_id')).run();
    invalidateAllCaches();
    return c.redirect(`/staff/event/${c.req.param('event_id')}/logs`);
});

// ============================
// LIVE CAMERA SCANNER & GATE CHECK-IN USP
// ============================

// Live Web-Camera Gate Scanner Page
app.get('/scanner/:event_id', async (c) => {
    const session = getSession(c);
    if (!session.username) return c.redirect('/');
    const eventId = parseInt(c.req.param('event_id'), 10);
    const db = getDb(c);
    const user = await getUser(db, session.username);

    // Permission check: superadmin or assigned staff
    if (session.role !== 'superadmin') {
        const access = await db.prepare("SELECT 1 FROM event_admins WHERE event_id = ? AND admin_username = ?").bind(eventId, session.username).first();
        if (!access) return c.redirect('/staff/events');
    }

    const sql = getSql(c);
    let event, totalCount = 0, checkedInCount = 0, recentScans = [];
    if (sql) {
        const rows = await sql`
            SELECT 
                (SELECT row_to_json(e) FROM events e WHERE e.event_id = ${eventId}) as event,
                (SELECT COUNT(*) FROM logs WHERE event_id = ${eventId}) as total_count,
                (SELECT COUNT(*) FROM logs WHERE event_id = ${eventId} AND status = 'checked_in') as checked_count,
                (SELECT json_agg(s) FROM (
                    SELECT log_id, ticket_token, data, status, checked_in_at, checked_in_by 
                    FROM logs 
                    WHERE event_id = ${eventId} AND status = 'checked_in' 
                    ORDER BY log_id DESC LIMIT 10
                ) s) as recent_scans;
        `;
        const r = rows && rows[0] ? rows[0] : {};
        event = r.event;
        totalCount = parseInt(r.total_count || '0', 10);
        checkedInCount = parseInt(r.checked_count || '0', 10);
        recentScans = (r.recent_scans || []).map(s => {
            let d = {};
            try { d = typeof s.data === 'object' ? s.data : JSON.parse(s.data); } catch { d = {}; }
            return {
                ...s,
                attendee_name: d['Full Name'] || d['Name'] || d['Student Name'] || Object.values(d)[0] || `Attendee #${s.log_id}`
            };
        });
    } else {
        const [eventRes, totalRes, checkedRes, recentRes] = await Promise.all([
            db.prepare("SELECT * FROM events WHERE event_id = ?").bind(eventId).first(),
            db.prepare("SELECT COUNT(*) as cnt FROM logs WHERE event_id = ?").bind(eventId).first(),
            db.prepare("SELECT COUNT(*) as cnt FROM logs WHERE event_id = ? AND status = 'checked_in'").bind(eventId).first(),
            db.prepare("SELECT * FROM logs WHERE event_id = ? AND status = 'checked_in' ORDER BY log_id DESC LIMIT 10").bind(eventId).all()
        ]);
        event = eventRes;
        totalCount = parseInt(totalRes?.cnt || '0', 10);
        checkedInCount = parseInt(checkedRes?.cnt || '0', 10);
        recentScans = (recentRes.results || []).map(s => {
            let d = {};
            try { d = JSON.parse(s.data); } catch { d = {}; }
            return {
                ...s,
                attendee_name: d['Full Name'] || d['Name'] || d['Student Name'] || Object.values(d)[0] || `Attendee #${s.log_id}`
            };
        });
    }

    if (!event) return c.redirect(session.role === 'superadmin' ? '/superadmin' : '/staff/events');

    const capacity = event.capacity || 100;
    const capacityPct = Math.min(100, Math.round((checkedInCount / capacity) * 100));

    return c.html(render('scanner', {
        user,
        event,
        totalCount,
        checkedInCount,
        capacity,
        capacityPct,
        recentScans,
        flash_messages: [],
        request: { path: `/scanner/${eventId}` }
    }));
});

// API - Live Web-Camera & Manual Scan Validator (Duplicate Prevention)
app.post('/api/scan', async (c) => {
    const session = getSession(c);
    if (!session.username) return c.json({ success: false, error: 'Unauthorized' }, 401);
    
    let body;
    try {
        body = await c.req.json();
    } catch {
        body = await c.req.parseBody();
    }

    const eventId = parseInt(body.event_id, 10);
    const token = (body.token || body.ticket_token || '').trim();

    if (!eventId || !token) {
        return c.json({ success: false, error: 'Missing event ID or ticket token' }, 400);
    }

    const db = getDb(c);
    const sql = getSql(c);

    // Look up attendee by ticket_token OR log_id
    let log;
    if (sql) {
        const rows = await sql`
            SELECT * FROM logs 
            WHERE event_id = ${eventId} AND (ticket_token = ${token} OR log_id::text = ${token})
            LIMIT 1;
        `;
        log = rows && rows[0] ? rows[0] : null;
    } else {
        log = await db.prepare("SELECT * FROM logs WHERE event_id = ? AND (ticket_token = ? OR log_id = ?)").bind(eventId, token, parseInt(token, 10) || 0).first();
    }

    if (!log) {
        return c.json({
            success: false,
            status: 'not_found',
            message: `INVALID PASS • No ticket registered with code "${token}".`
        });
    }

    let attendeeData = {};
    try {
        attendeeData = typeof log.data === 'object' ? log.data : JSON.parse(log.data);
    } catch {
        attendeeData = {};
    }

    const attendeeName = attendeeData['Full Name'] || attendeeData['Name'] || attendeeData['Student Name'] || Object.values(attendeeData)[0] || `Attendee #${log.log_id}`;

    // DUPLICATE PASS CHECK:
    if (log.status === 'checked_in') {
        return c.json({
            success: false,
            status: 'already_checked_in',
            message: 'DUPLICATE PASS DETECTED',
            details: `This pass was already checked in at ${log.checked_in_at || 'earlier'} by ${log.checked_in_by || 'gate staff'}.`,
            attendee_name: attendeeName,
            ticket_token: log.ticket_token || `PASS-${log.log_id}`,
            checked_in_at: log.checked_in_at
        });
    }

    // FIRST-TIME VALID CHECK-IN:
    const formattedTime = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    if (sql) {
        await sql`
            UPDATE logs 
            SET status = 'checked_in', checked_in_at = ${formattedTime}, checked_in_by = ${session.username} 
            WHERE log_id = ${log.log_id};
        `;
    } else {
        await db.prepare("UPDATE logs SET status = 'checked_in', checked_in_at = ?, checked_in_by = ? WHERE log_id = ?")
            .bind(formattedTime, session.username, log.log_id).run();
    }

    invalidateAllCaches();

    // Fetch updated totals for live counter
    let totalCount = 0, checkedInCount = 0;
    if (sql) {
        const counts = await sql`
            SELECT 
                (SELECT COUNT(*) FROM logs WHERE event_id = ${eventId}) as total,
                (SELECT COUNT(*) FROM logs WHERE event_id = ${eventId} AND status = 'checked_in') as checked;
        `;
        totalCount = parseInt(counts[0]?.total || '0', 10);
        checkedInCount = parseInt(counts[0]?.checked || '0', 10);
    }

    return c.json({
        success: true,
        status: 'checked_in',
        message: 'ACCESS GRANTED • CHECKED IN',
        attendee_name: attendeeName,
        ticket_token: log.ticket_token || `PASS-${log.log_id}`,
        checked_in_at: formattedTime,
        data: attendeeData,
        total_count: totalCount,
        checked_in_count: checkedInCount
    });
});

// API - Manual Check-in Toggle
app.post('/api/checkin/toggle/:log_id', async (c) => {
    const session = getSession(c);
    if (!session.username) return c.json({ error: 'Unauthorized' }, 401);
    const logId = parseInt(c.req.param('log_id'), 10);
    const db = getDb(c);
    const log = await db.prepare("SELECT * FROM logs WHERE log_id = ?").bind(logId).first();
    if (!log) return c.json({ error: 'Not found' }, 404);

    const newStatus = log.status === 'checked_in' ? 'registered' : 'checked_in';
    const checkinTime = newStatus === 'checked_in' ? new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : null;
    const checkinBy = newStatus === 'checked_in' ? session.username : null;

    await db.prepare("UPDATE logs SET status = ?, checked_in_at = ?, checked_in_by = ? WHERE log_id = ?")
        .bind(newStatus, checkinTime, checkinBy, logId).run();

    invalidateAllCaches();
    return c.json({ success: true, status: newStatus, checked_in_at: checkinTime });
});

// ============================
// DIGITAL PASS & ATTENDANCE
// ============================

// Public - View Digital Event Pass
app.get('/pass/:ticket_token', async (c) => {
    const token = c.req.param('ticket_token');
    const db = getDb(c);
    const sql = getSql(c);

    let log, event;
    if (sql) {
        const rows = await sql`
            SELECT l.*, row_to_json(e) as event 
            FROM logs l 
            JOIN events e ON l.event_id = e.event_id 
            WHERE l.ticket_token = ${token} OR l.log_id::text = ${token}
            LIMIT 1;
        `;
        if (rows && rows[0]) {
            log = rows[0];
            event = rows[0].event;
        }
    } else {
        log = await db.prepare("SELECT * FROM logs WHERE ticket_token = ? OR log_id = ?").bind(token, parseInt(token, 10) || 0).first();
        if (log) {
            event = await db.prepare("SELECT * FROM events WHERE event_id = ?").bind(log.event_id).first();
        }
    }

    if (!log || !event) return c.text('Digital Ticket Pass Not Found', 404);

    let data = {};
    try { data = typeof log.data === 'object' ? log.data : JSON.parse(log.data); } catch { data = {}; }
    const attendeeName = data['Full Name'] || data['Name'] || data['Student Name'] || Object.values(data)[0] || 'Attendee';

    const passToken = log.ticket_token || `PASS-${log.log_id}`;
    let qrSvg = '';
    try {
        qrSvg = await QRCode.toString(passToken, {
            type: 'svg',
            margin: 1,
            color: { dark: '#0b0f19', light: '#ffffff' }
        });
    } catch {}

    const formattedTime = new Date(log.timestamp).toLocaleString('en-US', {
        month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit'
    });

    return c.html(render('attend_success', {
        event,
        ticket_token: passToken,
        attendee_name: attendeeName,
        data,
        timestamp: formattedTime,
        status: log.status || 'registered',
        checked_in_at: log.checked_in_at || null,
        qr_svg: qrSvg,
        request: { path: `/pass/${token}` }
    }));
});

// Public - Register / Attend Event Form
app.get('/attend/:event_id', async (c) => {
    const eventId = parseInt(c.req.param('event_id'), 10);
    const db = getDb(c);
    const sql = getSql(c);

    let event, fields, totalCount = 0;
    if (sql) {
        const rows = await sql`
            SELECT 
                (SELECT row_to_json(e) FROM events e WHERE e.event_id = ${eventId}) as event,
                (SELECT json_agg(f) FROM (SELECT * FROM event_fields WHERE event_id = ${eventId} ORDER BY field_order ASC, field_id ASC) f) as fields,
                (SELECT COUNT(*) FROM logs WHERE event_id = ${eventId}) as total_count;
        `;
        const r = rows && rows[0] ? rows[0] : {};
        event = r.event;
        fields = r.fields || [];
        totalCount = parseInt(r.total_count || '0', 10);
    } else {
        const [eventRes, fieldsRes, countRes] = await Promise.all([
            db.prepare("SELECT * FROM events WHERE event_id = ?").bind(eventId).first(),
            db.prepare("SELECT * FROM event_fields WHERE event_id = ? ORDER BY field_order ASC, field_id ASC").bind(eventId).all(),
            db.prepare("SELECT COUNT(*) as cnt FROM logs WHERE event_id = ?").bind(eventId).first()
        ]);
        event = eventRes;
        fields = fieldsRes.results || [];
        totalCount = parseInt(countRes?.cnt || '0', 10);
    }

    if (!event) return c.text('Event not found', 404);

    const capacity = event.capacity || 100;
    const spotsRemaining = Math.max(0, capacity - totalCount);

    return c.html(render('attend', {
        event,
        fields,
        totalCount,
        capacity,
        spotsRemaining,
        flash_messages: [],
        request: { path: `/attend/${eventId}` }
    }));
});

// Public - Submit Attendance & Generate Instant Digital QR Pass
app.post('/attend/:event_id', async (c) => {
    const eventId = parseInt(c.req.param('event_id'), 10);
    const db = getDb(c);
    const sql = getSql(c);
    const body = await c.req.parseBody();

    let event, fields;
    if (sql) {
        const rows = await sql`
            SELECT 
                (SELECT row_to_json(e) FROM events e WHERE e.event_id = ${eventId}) as event,
                (SELECT json_agg(f) FROM (SELECT * FROM event_fields WHERE event_id = ${eventId} ORDER BY field_order ASC, field_id ASC) f) as fields;
        `;
        const r = rows && rows[0] ? rows[0] : {};
        event = r.event;
        fields = r.fields || [];
    } else {
        event = await db.prepare("SELECT * FROM events WHERE event_id = ?").bind(eventId).first();
        fields = (await db.prepare("SELECT * FROM event_fields WHERE event_id = ? ORDER BY field_order ASC, field_id ASC").bind(eventId).all()).results || [];
    }

    if (!event) return c.text('Event not found', 404);

    const data = {};
    for (const field of fields) {
        data[field.field_label] = body[field.field_label] || '';
    }

    // Default fallback if event has no fields
    if (fields.length === 0) {
        data['Full Name'] = body['Full Name'] || body.name || 'Attendee';
        data['Email'] = body['Email'] || body.email || '';
    }

    const attendeeName = data['Full Name'] || data['Name'] || data['Student Name'] || Object.values(data)[0] || 'Attendee';

    // Generate unique verifiable pass token
    const randCode = Math.random().toString(36).substring(2, 6).toUpperCase();
    const timeCode = Date.now().toString(36).substring(4).toUpperCase();
    const ticketToken = `PASS-E${eventId}-${randCode}-${timeCode}`;

    const now = new Date();
    await db.prepare("INSERT INTO logs (event_id, data, timestamp, ticket_token, status) VALUES (?, ?, ?, ?, 'registered')")
        .bind(eventId, JSON.stringify(data), now.toISOString(), ticketToken).run();

    invalidateAllCaches();

    // Generate high-res SVG QR Code of the ticket token
    let qrSvg = '';
    try {
        qrSvg = await QRCode.toString(ticketToken, {
            type: 'svg',
            margin: 1,
            color: { dark: '#0b0f19', light: '#ffffff' }
        });
    } catch {}

    const formattedTime = now.toLocaleString('en-US', {
        month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit'
    });

    return c.html(render('attend_success', {
        event,
        ticket_token: ticketToken,
        attendee_name: attendeeName,
        data,
        timestamp: formattedTime,
        status: 'registered',
        checked_in_at: null,
        qr_svg: qrSvg,
        request: { path: `/attend/${eventId}` }
    }));
});

// Dynamic QR Code by token
app.get('/qr_token/:token', async (c) => {
    const token = c.req.param('token');
    try {
        const svg = await QRCode.toString(token, {
            type: 'svg',
            margin: 1,
            color: { dark: '#0b0f19', light: '#ffffff' }
        });
        return new Response(svg, {
            headers: {
                'Content-Type': 'image/svg+xml; charset=utf-8',
                'Cache-Control': 'public, max-age=86400'
            }
        });
    } catch {
        return c.text('QR generation error', 500);
    }
});

// QR Code for Event Registration URL
app.get('/qr_code/:event_id', async (c) => {
    const eventId = c.req.param('event_id');
    const baseUrl = getBaseUrl(c);
    const url = `${baseUrl}/attend/${eventId}`;
    try {
        const svg = await QRCode.toString(url, {
            type: 'svg',
            margin: 1,
            color: {
                dark: '#0b0f19',
                light: '#ffffff'
            }
        });
        return new Response(svg, {
            headers: {
                'Content-Type': 'image/svg+xml; charset=utf-8',
                'Cache-Control': 'public, max-age=86400'
            }
        });
    } catch {
        const qrApiUrl = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(url)}`;
        const response = await fetch(qrApiUrl);
        return new Response(await response.arrayBuffer(), { headers: { 'Content-Type': 'image/png' } });
    }
});

// API - Event Logs (Real-time polling)
app.get('/api/event/:event_id/logs', async (c) => {
    const session = getSession(c);
    if (!session.username) return c.json({ error: 'Unauthorized' }, 401);
    const eventId = c.req.param('event_id');
    const sinceId = parseInt(c.req.query('since') || '0');
    const db = getDb(c);

    const logsRaw = (await db.prepare("SELECT * FROM logs WHERE event_id = ? AND log_id > ? ORDER BY log_id DESC").bind(eventId, sinceId).all()).results || [];
    const logs = logsRaw.map(l => {
        try { l.data = typeof l.data === 'object' ? l.data : JSON.parse(l.data); } catch { l.data = {}; }
        try {
            l.formatted_timestamp = new Date(l.timestamp).toLocaleString('en-US', {
                month: 'short', day: 'numeric', year: 'numeric',
                hour: '2-digit', minute: '2-digit', hour12: true
            });
        } catch {
            l.formatted_timestamp = l.timestamp;
        }
        l.status = l.status || 'registered';
        l.ticket_token = l.ticket_token || `PASS-${l.log_id}`;
        return l;
    });
    return c.json({ logs });
});

// API - Export Event Logs to CSV (Includes Ticket Pass ID & Check-in Status)
app.get('/api/event/:event_id/export', async (c) => {
    const session = getSession(c);
    if (!session.username) return c.redirect('/');
    const eventId = c.req.param('event_id');
    const db = getDb(c);

    const event = await db.prepare("SELECT * FROM events WHERE event_id = ?").bind(eventId).first();
    if (!event) return c.text('Event not found', 404);

    const fields = (await db.prepare("SELECT * FROM event_fields WHERE event_id = ? ORDER BY field_order ASC, field_id ASC").bind(eventId).all()).results || [];
    const logsRaw = (await db.prepare("SELECT * FROM logs WHERE event_id = ? ORDER BY log_id DESC").bind(eventId).all()).results || [];

    const fieldLabels = fields.map(f => f.field_label);
    const headers = ['Log ID', 'Ticket Token', 'Gate Status', 'Checked In At', 'Checked In By', 'Registered Timestamp', ...fieldLabels];

    const escapeCsv = (str) => {
        if (str === null || str === undefined) return '""';
        const s = String(str).replace(/"/g, '""');
        return `"${s}"`;
    };

    let csv = headers.map(escapeCsv).join(',') + '\r\n';

    for (const log of logsRaw) {
        let dataObj = {};
        try { dataObj = typeof log.data === 'object' ? log.data : JSON.parse(log.data); } catch { dataObj = {}; }
        const row = [
            log.log_id,
            log.ticket_token || `PASS-${log.log_id}`,
            log.status || 'registered',
            log.checked_in_at || 'N/A',
            log.checked_in_by || 'N/A',
            log.timestamp,
            ...fieldLabels.map(label => dataObj[label] ?? '')
        ];
        csv += row.map(escapeCsv).join(',') + '\r\n';
    }

    const safeFilename = (event.event_name || `event_${eventId}`).replace(/[^a-zA-Z0-9_-]/g, '_');
    return new Response(csv, {
        headers: {
            'Content-Type': 'text/csv; charset=utf-8',
            'Content-Disposition': `attachment; filename="${safeFilename}_gate_report.csv"`
        }
    });
});

// Queue Status
app.get('/queue_status', (c) => c.json({ size: 0 }));

// Uploaded files (profile pictures) placeholder
app.get('/uploads/:filename', (c) => {
    return c.redirect('https://api.dicebear.com/7.x/initials/svg?seed=' + c.req.param('filename'));
});

export default app;
