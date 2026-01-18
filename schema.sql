-- schema.sql
-- Initialize Cloudflare D1 Database for EventLogger

CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT,
    role TEXT,
    name TEXT,
    phone TEXT,
    address TEXT,
    profile_pic TEXT,
    approved INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_name TEXT
);

CREATE TABLE IF NOT EXISTS event_fields (
    field_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    field_label TEXT,
    field_type TEXT,
    is_required INTEGER,
    field_order INTEGER
);

CREATE TABLE IF NOT EXISTS event_admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    admin_username TEXT
);

CREATE TABLE IF NOT EXISTS logs (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    data TEXT,
    timestamp TEXT
);

-- Default Superadmin: admin/admin
INSERT OR IGNORE INTO users (username, password, role, name, phone, address, approved) 
VALUES ('admin', 'admin', 'superadmin', 'Super Admin', '000-000-0000', 'Server Room', 1);
