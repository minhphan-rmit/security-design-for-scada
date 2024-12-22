# Secure Flask Server Setup

This document provides step-by-step instructions for setting up and running the secure Flask server implementing defense-in-depth principles.

## Prerequisites

Before starting, ensure you have the following:

- **Python 3.8 or newer**
- **pip** (Python package manager)
- **Virtual Environment (optional)** for isolating dependencies
- **Database** (SQLite by default, or another SQLAlchemy-compatible database if configured)

## Setup Instructions

### 1. Clone the Repository

Clone the repository containing the Flask server code:

```bash
git clone <repository_url>
cd <repository_directory>
```

### 2. Create a Virtual Environment (Optional)

It is recommended to use a virtual environment to isolate dependencies:

```bash
python3 -m venv venv
source venv/bin/activate # For Linux/Mac
venv\Scripts\activate   # For Windows
```

### 3. Install Required Dependencies

Install the dependencies listed in `requirements.txt`:

```bash
pip install -r requirements.txt
```

### 4. Set Up Environment Variables

Create a `.env` file in the root of the project directory and define the following environment variables:

```env
SECRET_KEY=<your_secret_key>
HMAC_KEY=<your_hmac_key>
JWT_SECRET=<your_jwt_secret>
DATABASE_URI=<your_database_uri> # Default is sqlite:///security_demo.db
FLASK_ENV=production            # Set to 'development' for debugging
ALERT_EMAIL=<alert_email>
ALERT_RECIPIENT=<security_team_email>
```

### 5. Initialize the Database

Run the following commands to initialize the database:

```bash
flask db init
flask db migrate -m "Initial migration."
flask db upgrade
```

This will create the database schema based on the defined models.

### 6. Create Default Users

The server will automatically create the following default users if they do not exist:

- **Admin User**:
  - Username: `admin`
  - Password: `adminpassword`
  - Role: `admin`

- **Normal User**:
  - Username: `user`
  - Password: `userpassword`
  - Role: `user`

### 7. Start the Server

Run the server using the following command:

```bash
python app.py
```

The server will start on `https://localhost:5000` with an auto-generated SSL certificate for development purposes.

### 8. Access the Server

You can access the server in a web browser or via API tools like Postman using the base URL:

```
https://localhost:5000
```

## Key Features

- **Rate Limiting**: Protects against DoS attacks.
- **Role-Based Access Control (RBAC)**: Enforces access restrictions based on user roles.
- **Secure Defaults**: Sessions and cookies are secured.
- **Content Security Policy (CSP)**: Mitigates XSS attacks.
- **Two-Factor Authentication (TOTP)**: Enhances login security.
- **JWT Authentication**: Protects API routes.
- **File Upload Scanning**: Ensures uploaded files are malware-free.

## API Endpoints

### Public Endpoints

- **Health Check**: `GET /`
- **Register**: `POST /register`
- **Login**: `POST /login`

### Protected Endpoints (Requires Authentication)

- **File Upload**: `POST /upload_file`
- **Upload Control Logic (Admin Only)**: `POST /upload_logic`

## Additional Notes

### Running in Production

- Use a proper **SSL certificate** instead of the auto-generated one.
- Set `FLASK_ENV=production` in the `.env` file.
- Use a robust database like PostgreSQL or MySQL for production.

### Logging and Monitoring

Logs are written to the console. Configure a centralized logging system for better monitoring in production.

### Alerts

Ensure the `ALERT_EMAIL` and `ALERT_RECIPIENT` variables are configured for security notifications.

---

For additional support, contact the development team or refer to the code comments for detailed explanations.
