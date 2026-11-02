# EventLogger QMS

A high-performance Event Logging, Dynamic Registration & Attendance Management System built with **Hono** and **Cloudflare Workers (D1 SQLite Database)**.

---

## 🌟 Key Features & USPs

- **Super Admin Command Center**:
  - Create and manage campus events.
  - Approve or reject pending staff registrations.
  - Assign approved staff organizers to specific events.
  - Dynamically customize form fields per event (Text, Email, Phone, Number, Required validation).
- **Dynamic QR Code Attendance**:
  - Automatically generates sharp SVG QR codes for each event.
  - Zero external network dependencies for offline/local reliability.
  - Instant direct attendance link generation.
- **Live Logs & Real-Time Monitoring**:
  - Live polling dashboard showing student responses in real time.
  - Dynamic client-side search/filter across any custom field.
  - Single-click **CSV Export** to download attendee records as an Excel-ready spreadsheet.
- **Cyber / Tech Themed UI**:
  - Responsive dark-mode interface built with Tailwind CSS, animated stars background, and 3D Spline elements.
- **Serverless & Edge Ready**:
  - Powered by Hono + Cloudflare Workers + D1 database for sub-10ms global latency.

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- **Node.js** (v18 or higher)
- **npm**

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/aamirldz/eventlogger.git
cd eventlogger

# Install dependencies
npm install
```

### 3. Initialize Local D1 Database
Execute the database schema locally:
```bash
npx wrangler d1 execute eventlogger-db --local --file=schema.sql
```

### 4. Run Development Server
```bash
npm run dev
# Or: npx wrangler dev --port 8787
```

Open your browser at **`http://localhost:8787`**.

---

## 🔑 Default Credentials

| Role | Username | Password |
|---|---|---|
| **Super Admin** | `admin` | `admin` |

*Staff can register from the `/register` page and must be approved by the Super Admin before logging in.*

---

## 📂 Project Structure

```text
├── src/
│   └── index.js          # Core Hono application & Jinja-compatible template engine
├── templates/            # HTML templates (Layout, Admin, Staff, Attend, Logs)
│   ├── components/       # Reusable components (Robot, User Header)
│   ├── staff/            # Staff dashboard, event list, live logs
│   └── superadmin/       # Admin dashboard, staff manager, form editor
├── static/
│   └── css/style.css     # Cyber theme CSS
├── schema.sql            # SQLite / Cloudflare D1 database schema
├── wrangler.toml         # Cloudflare Workers configuration
└── package.json          # Node dependencies and scripts
```

---

## ☁️ Deployment (Cloudflare Workers)

1. Create your remote D1 database:
   ```bash
   npx wrangler d1 create eventlogger-db
   ```
2. Apply the schema remotely:
   ```bash
   npx wrangler d1 execute eventlogger-db --remote --file=schema.sql
   ```
3. Deploy:
   ```bash
   npm run deploy
   ```
