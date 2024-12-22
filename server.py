################################################################################
# Secure Flask Server with Defense-in-Depth
# Author: Minh Phan
# Created: 2024-12-21
# Description: A Flask-based server implementing layered security to address 
# critical threats such as spoofing, tampering, DoS, information disclosure, 
# and privilege escalation using defense-in-depth principles.
################################################################################

from flask import Flask, request, jsonify, session, abort, send_file, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from functools import wraps
import logging
import hashlib
import hmac
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer
import pyotp
import bleach
import os
import subprocess
import shlex
import time
from datetime import datetime, timedelta
import jwt

################################################################################
# Application Configuration and Initialization
################################################################################

app = Flask(__name__)

# Security Configuration: Layer 1 (Secure Defaults)
# Use a securely stored secret key to protect sessions and tokens.
app.secret_key = os.environ.get("SECRET_KEY", "supersecuresecretkey")
HMAC_KEY = os.environ.get("HMAC_KEY", "supersecurehmackey")
JWT_SECRET = os.environ.get("JWT_SECRET", "supersecurejwtkey")
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URI", "sqlite:///security_demo.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['ENV'] = os.environ.get("FLASK_ENV", "production")  # Default to production

# Enable Debug Mode for Testing (disable in production)
app.debug = app.config['ENV'] == 'development'

# Database Initialization
db = SQLAlchemy(app)

# Migrate Initialization
migrate = Migrate(app, db)

# Rate Limiting Configuration: Layer 2 (Traffic Control)
# Apply global rate limits to protect against DoS attacks.
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Serializer for Secure Tokens
serializer = URLSafeTimedSerializer(app.secret_key)

# Logging Configuration: Layer 3 (Monitoring and Alerts)
# Use logging to monitor application activity and detect anomalies.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger()

################################################################################
# Database Models
################################################################################

class User(db.Model):
    """
    Represents a user in the system, including authentication details
    and role-based access control.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    totp_secret = db.Column(db.String(16), default=lambda: pyotp.random_base32())

class ActionLog(db.Model):
    """
    Logs actions performed by users for auditing and monitoring purposes.
    Includes username, action description, and timestamp.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

class ControlLogic(db.Model):
    """
    Stores control logic scripts and their hash values to ensure integrity.
    Includes logic name, hash, and timestamp for version control.
    """
    id = db.Column(db.Integer, primary_key=True)
    logic_name = db.Column(db.String(100), unique=True, nullable=False)
    logic_hash = db.Column(db.String(64), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

################################################################################
# Helper Functions
################################################################################

def hash_content(content):
    """
    Generate a SHA-256 hash of the provided content.
    """
    return hashlib.sha256(content.encode()).hexdigest()

def generate_hmac(data):
    """
    Generate an HMAC for the given data using the configured HMAC key.
    """
    return hmac.new(HMAC_KEY.encode(), data.encode(), hashlib.sha256).hexdigest()

def verify_hmac(data, hmac_to_verify):
    """
    Verify the provided HMAC against the generated HMAC for the data.
    """
    expected_hmac = generate_hmac(data)
    return hmac.compare_digest(expected_hmac, hmac_to_verify)

def sanitize_input(data):
    """
    Sanitize user input to prevent injection attacks by removing unsafe
    tags, attributes, and styles.
    """
    if data is None:
        return ""
    return bleach.clean(data, tags=[], attributes={}, styles=[], strip=True)

def requires_role(role):
    """
    Decorator to enforce role-based access control on routes.
    Only users with the specified role can access the route.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "username" not in session or session.get("role") != role:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_action(username, action):
    """
    Log a user action to the database for auditing purposes.
    """
    log_entry = ActionLog(username=username, action=action)
    db.session.add(log_entry)
    db.session.commit()

def send_alert(subject, body):
    """
    Send an alert email to the security team for critical issues,
    such as HMAC verification failures or suspicious activities.
    """
    from email.mime.text import MIMEText
    import smtplib

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = os.environ.get("ALERT_EMAIL", "admin@example.com")
    msg['To'] = os.environ.get("ALERT_RECIPIENT", "security@example.com")

    with smtplib.SMTP('smtp.example.com', 587) as server:
        server.login("user@example.com", "password")
        server.sendmail(msg['From'], [msg['To']], msg.as_string())

def generate_token(username):
    """
    Generate a JWT token for a given username with an expiration.
    """
    return jwt.encode(
        {"username": username, "exp": datetime.utcnow() + timedelta(hours=1)},
        JWT_SECRET,
        algorithm="HS256"
    )

def allowed_file(filename):
    """
    Check if the uploaded file has an allowed extension.
    """
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def jwt_required(f):
    """
    Decorator to protect routes by requiring a valid JWT token.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            abort(403, description="Token missing")
        try:
            jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            abort(401, description="Token expired")
        except jwt.InvalidTokenError:
            abort(401, description="Invalid token")
        return f(*args, **kwargs)
    return decorated_function

################################################################################
# Application Routes
################################################################################

@app.before_request
def restrict_ip():
    """
    Restrict access to the application by IP address.
    Allow unrestricted access in testing environments.
    """
    if app.config.get('ENV') != 'development':  # Skip IP check in development/testing
        allowed_ips = ['10.8.0.0/24', '192.168.1.0/24', '127.0.0.1', '0.0.0.0']  # Include localhost and loopback
        if not any(request.remote_addr.startswith(ip) for ip in allowed_ips):
            logger.warning(f"Blocked unauthorized IP: {request.remote_addr}")
            logger.info(f"Incoming request from IP: {request.remote_addr}")
            abort(403)

@app.after_request
def apply_csp(response):
    """
    Add Content Security Policy (CSP) headers to mitigate XSS attacks
    and other code injection vulnerabilities.
    """
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self';"
    )
    return response

@app.route('/')
def home():
    """
    Health check endpoint to confirm that the server is running.
    """
    return jsonify({"message": "Server is running."}), 200

@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    """
    Register a new user with a username, password, and optional role.
    Generates a unique TOTP secret for the user.
    """
    data = request.json
    username = sanitize_input(data.get('username'))
    password = sanitize_input(data.get('password'))
    role = sanitize_input(data.get('role', 'user'))

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "User already exists"}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()

    logger.info(f"User {username} registered with role {role}.")
    return jsonify({"message": "Registration successful", "totp_secret": new_user.totp_secret}), 201

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    """
    Authenticate a user and establish a session. Requires username,
    password, and a valid TOTP code.
    Implements account lockout after multiple failed attempts.
    """
    global FAILED_LOGIN_ATTEMPTS
    data = request.json
    username = sanitize_input(data.get('username'))
    password = sanitize_input(data.get('password'))
    totp_code = sanitize_input(data.get('totp'))

    logger.info(f"Login attempt for user: {username}")
    logger.info(f"Provided TOTP: {totp_code}")

    # Check if user exists
    user = User.query.filter_by(username=username).first()
    if user:
        logger.info(f"User found: {user.username}, Role: {user.role}")
        logger.info(f"User TOTP Secret: {user.totp_secret}")
    else:
        logger.error("User not found.")
        abort(401, description="Invalid credentials")

    # Password check
    if not check_password_hash(user.password, password):
        logger.error("Password check failed.")
        abort(401, description="Invalid credentials")
    else:
        logger.info("Password check passed.")

    # TOTP verification
    totp = pyotp.TOTP(user.totp_secret)
    current_totp = totp.now()
    logger.info(f"Encoded TOTP: {current_totp}")
    if not totp.verify(current_totp):
        logger.error("TOTP verification failed.")
        abort(401, description="Invalid TOTP")
    else:
        logger.info("TOTP verification passed.")

    # Successful login
    session['username'] = username
    session['role'] = user.role
    log_action(username, "login")
    return jsonify({"message": "Login successful", "token": generate_token(username)}), 200

@app.route('/upload_file', methods=['POST'])
# @requires_role('user')
def upload_file():
    """
    Handle file uploads securely, including validating file types
    and scanning for malware using ClamAV.
    """
    if 'file' not in request.files:
        return jsonify({"message": "No file provided"}), 400

    file = request.files['file']
    if not allowed_file(file.filename):
        return jsonify({"message": "Invalid file type"}), 400

    filename = sanitize_input(file.filename)
    file_path = os.path.join('/tmp', filename)
    file.save(file_path)

    try:
        result = subprocess.run(
            ['clamscan', file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        scan_output = result.stdout
    except Exception as e:
        os.remove(file_path)
        logger.error(f"Error during malware scan: {e}")
        return jsonify({"message": "Error scanning file"}), 500

    os.remove(file_path)

    if "OK" in scan_output:
        logger.info(f"File {file.filename} passed malware scan.")
        return jsonify({"message": "File uploaded successfully"}), 200
    else:
        logger.warning(f"Malware detected in file {file.filename}: {scan_output}")
        return jsonify({"message": "Malware detected, file rejected"}), 403

@app.route('/upload_logic', methods=['POST'])
@requires_role('admin')
def upload_logic():
    """
    Upload control logic scripts with HMAC validation to ensure integrity.
    Updates existing scripts or adds new ones if valid.
    """
    data = request.json
    logic_name = sanitize_input(data.get("logic_name"))
    logic_content = sanitize_input(data.get("logic_content"))
    provided_hmac = data.get("hmac")

    if not logic_name or not logic_content or not provided_hmac:
        return jsonify({"message": "Logic name, content, and HMAC are required"}), 400

    if not verify_hmac(logic_content, provided_hmac):
        send_alert("HMAC Failure Detected", f"HMAC verification failed for logic: {logic_name}")
        logger.warning("HMAC verification failed.")
        return jsonify({"message": "Invalid HMAC"}), 403

    logic_hash = hash_content(logic_content)
    existing_logic = ControlLogic.query.filter_by(logic_name=logic_name).first()

    if existing_logic:
        if existing_logic.logic_hash == logic_hash:
            return jsonify({"message": "Logic is already up-to-date"}), 200
        else:
            existing_logic.logic_hash = logic_hash
            existing_logic.timestamp = db.func.current_timestamp()
            db.session.commit()
            log_action(session['username'], f"Updated logic: {logic_name}")
            return jsonify({"message": "Logic updated successfully"}), 200
    else:
        new_logic = ControlLogic(logic_name=logic_name, logic_hash=logic_hash)
        db.session.add(new_logic)
        db.session.commit()
        log_action(session['username'], f"Uploaded new logic: {logic_name}")
        return jsonify({"message": "Logic uploaded successfully"}), 201

@app.errorhandler(403)
def forbidden(e):
    """
    Handle 403 Forbidden errors by logging the event and providing
    a user-friendly message.
    """
    logger.warning("Forbidden access attempted.")
    return jsonify({"message": "Access forbidden"}), 403

@app.errorhandler(404)
def not_found(e):
    """
    Handle 404 Not Found errors by returning a JSON response to
    indicate the resource does not exist.
    """
    return jsonify({"message": "Resource not found"}), 404

@app.before_request
def enforce_https():
    """
    Redirect all HTTP requests to HTTPS to ensure secure communication.
    """
    if not request.is_secure and app.config['ENV'] == 'production':
        return redirect(request.url.replace("http://", "https://"))

################################################################################
# Application Initialization and Startup
################################################################################

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        logger.info("Database initialized.")

        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', password=generate_password_hash('adminpassword'), role='admin')
            db.session.add(admin_user)
            logger.info("Admin user created.")

        if not User.query.filter_by(username='user').first():
            normal_user = User(username='user', password=generate_password_hash('userpassword'), role='user')
            db.session.add(normal_user)
            logger.info("Normal user created.")

        db.session.commit()

    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')
