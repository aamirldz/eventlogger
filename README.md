# EventLogger QMS

A robust Event Logging and Queue Management System built with Flask.

## Features
- **Super Admin Dashboard**: Create events, manage admins, design forms dynamically.
- **Admin Dashboard**: View assigned events, monitor live logs.
- **Dynamic Forms**: Admins can create custom fields for each event.
- **QR Code Attendance**: Automatically generates QR codes for events.
- **Live Logging**: Real-time log monitoring with background processing.
- **Responsive UI**: "Cyber/Tech" themed UI using Tailwind CSS and Framer Motion.

## Installation

1.  Clone the repository.
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3.  Run the application:
    ```bash
    python app.py
    ```
    Or use Gunicorn:
    ```bash
    gunicorn app:app
    ```
4.  Open `http://localhost:5002`.
5.  **Default Credentials**:
    -   **Username**: `admin`
    -   **Password**: `admin`

## Deployment

### GitHub
1.  Initialize git: `git init`
2.  Add files: `git add .`
3.  Commit: `git commit -m "Initial commit"`
4.  Push to your repository.

### Hosting Suggestions
This is a **Python/Flask** application with a **SQLite** database and local file uploads.

-   **Render / Railway / Fly.io**: Best options. They support Python apps easily.
    -   *Note*: SQLite and `uploads/` are **ephemeral** on many free tiers (data is lost on restart).
    -   **Production Recommendation**: Use a persistent volume (Railway/Render allow this) OR switch to PostgreSQL/S3 for storage.
-   **Cloudflare**:
    -   **Cloudflare Pages**: Cannot host this (it's for static sites).
    -   **Cloudflare Workers**: Supports Python but requires significant changes to code structure.
    -   **Recommendation**: Host on Railway/Render, and use Cloudflare for DNS/CDN/DDoS protection.

## Project Structure
-   `app.py`: Main application logic.
-   `templates/`: HTML templates.
-   `static/`: CSS, JS, images.
-   `uploads/`: User uploaded profile pics.
-   `event.db`: SQLite database.
