# ===========================
# Portfolio Website - Flask Application
# Copyright (c) 2026 Kyei-Baffour Emmanuel Frimpong
# All rights reserved.
# ===========================

# ===========================
# IMPORTS - All required libraries  
# ===========================
from flask import Flask, render_template, request, flash, redirect, url_for, jsonify, send_file, session
from markupsafe import escape
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail, Message
from datetime import datetime, timezone
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from functools import wraps
import os
import threading
import bleach

# Load environment variables from .env file
load_dotenv()

# Import models
from models import db, ContactMessage, AdminUser, Project, Experience, Certification, Skill, ContactInfo

# ===========================
# FLASK APP CONFIGURATION
# ===========================
app = Flask(__name__)

# Secret key for session security and CSRF protection (loaded from .env)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'

# Email configuration for contact form functionality
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')  # Your Gmail address
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')  # Your Gmail app password
mail = Mail(app)  # Initialize Flask-Mail

# ===========================
# DATABASE CONFIGURATION
# ===========================
# Database configuration (supports both SQLite and PostgreSQL)
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql+psycopg2://", 1)

# Add SSL configuration for PostgreSQL on Render
if database_url and 'postgresql' in database_url:
    if '?' in database_url:
        database_url += '&sslmode=require'
    else:
        database_url += '?sslmode=require'

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///portfolio.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

# ===========================
# SECURITY CONFIGURATION
# ===========================
# Session Configuration for Enhanced Security
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'  # HTTPS only in production
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent XSS access to session cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes session timeout

# CSRF Protection Configuration
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour
app.config['WTF_CSRF_SSL_STRICT'] = os.environ.get('FLASK_ENV') == 'production'

# Initialize security extensions
csrf = CSRFProtect(app)
db.init_app(app)

# Rate limiting configuration for DDoS protection
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",  # Use memory storage for rate limiting
    headers_enabled=True  # Include rate limit headers in responses
)

# Thread-safe database initialization
_db_init_lock = threading.Lock()
_db_initialized = False

@app.before_request
def create_tables():
    """Thread-safe database initialization."""
    global _db_initialized
    if not _db_initialized:
        with _db_init_lock:
            if not _db_initialized:
                try:
                    db.create_all()
                    _db_initialized = True
                except Exception as e:
                    app.logger.error(f'Database initialization failed: {repr(e)}')
                    raise

# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    # Prevent clickjacking attacks
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Enable XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Content Security Policy (basic policy)
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self';"
    )
    
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    return response

# ===========================
# ROUTES - URL endpoints
# ===========================

@app.route('/debug/email-test')
def debug_email_test():
    """Debug route to test email configuration"""
    if app.config.get('FLASK_ENV') != 'production':
        try:
            if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
                return {'status': 'error', 'message': 'Email not configured'}
            
            # Test email sending
            msg = Message(
                subject='Test Email',
                sender=app.config['MAIL_USERNAME'],
                recipients=[app.config['MAIL_USERNAME']]
            )
            msg.body = 'This is a test email to verify configuration.'
            
            mail.send(msg)
            return {'status': 'success', 'message': 'Test email sent successfully'}
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    else:
        return {'status': 'disabled', 'message': 'Debug route disabled in production'}

@app.route('/debug')
def debug_data():
    """Debug route to check database content"""
    projects_count = Project.query.count()
    certs_count = Certification.query.count()
    exp_count = Experience.query.count()
    skills_count = Skill.query.count()
    admin_count = AdminUser.query.count()
    admin_password_env = os.environ.get('ADMIN_PASSWORD', 'NOT_SET')
    
    return {
        'projects': projects_count,
        'certifications': certs_count,
        'experience': exp_count,
        'skills': skills_count,
        'admin_users': admin_count,
        'admin_password_configured': admin_password_env != 'NOT_SET',
        'cert_data': [{'name': c.name, 'issuer': c.issuer} for c in Certification.query.all()]
    }

@app.route('/debug/recreate-admin')
def recreate_admin():
    """Debug route to recreate admin user"""
    try:
        from models import force_recreate_admin
        success = force_recreate_admin()
        
        if success:
            return {'status': 'success', 'message': 'Admin user recreated with current environment password'}
        else:
            return {'status': 'error', 'message': 'Failed to recreate admin user'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

@app.route('/')
def home():
    """Homepage with featured projects and sections."""
    projects = Project.query.limit(3).all()
    skills = {skill.category: {'items': skill.get_items(), 'level': skill.level} for skill in Skill.query.all()}
    contact_info = ContactInfo.query.first()
    experience = Experience.query.limit(2).all()
    certifications = Certification.query.limit(3).all()
    
    return render_template('index.html', 
                         projects=projects,
                         skills=skills,
                         contact_info=contact_info,
                         experience=experience,
                         certifications=certifications,
                         current_year=datetime.now().year)

@app.route('/projects')
def all_projects():
    """All projects page with complete project portfolio."""
    projects = Project.query.all()
    contact_info = ContactInfo.query.first()
    
    return render_template('projects.html', 
                         projects=projects,
                         contact_info=contact_info,
                         current_year=datetime.now().year)

@app.route('/project/<int:project_id>')
def project_detail(project_id):
    """Project case study detail page."""
    project = Project.query.get_or_404(project_id)
    contact_info = ContactInfo.query.first()
    
    return render_template('project_detail.html',
                         project=project,
                         contact_info=contact_info,
                         current_year=datetime.now().year)

@app.route('/experience')
def experience():
    """Experience and timeline page with professional background."""
    experience = Experience.query.all()
    certifications = Certification.query.all()
    contact_info = ContactInfo.query.first()
    
    return render_template('experience.html',
                         experience=experience,
                         certifications=certifications,
                         contact_info=contact_info,
                         current_year=datetime.now().year)

@app.route('/resume')
def download_resume():
    """Download CV file from static folder."""
    try:
        return send_file(
            'static/documents/Emmanuel_Frimpong_CV.pdf',
            as_attachment=True,
            download_name='Emmanuel_Frimpong_CV.pdf',
            mimetype='application/pdf'
        )
    except FileNotFoundError:
        flash('Resume file not found. Please contact me directly for my CV.', 'error')
        return redirect(url_for('home'))
    except Exception as e:
        app.logger.error(f'Resume download error: {repr(e)}')
        flash('Sorry, there was an error downloading the resume. Please try again later.', 'error')
        return redirect(url_for('home'))

@app.route('/contact', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def contact():
    """Contact page with working form that sends emails and stores in database"""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        message = request.form.get('message', '').strip()
        
        if not all([name, email, message]):
            flash('Please fill in all required fields.', 'error')
            return redirect(url_for('home') + '#contact')
        
        if len(name) < 2 or len(name) > 100:
            flash('Please enter a valid name (2-100 characters).', 'error')
            return redirect(url_for('home') + '#contact')
        
        if '@' not in email or '.' not in email or len(email) > 255:
            flash('Please enter a valid email address.', 'error')
            return redirect(url_for('home') + '#contact')
        
        if len(message) < 10 or len(message) > 1000:
            flash('Message must be between 10-1000 characters.', 'error')
            return redirect(url_for('home') + '#contact')
        
        try:
            clean_message = bleach.clean(message, tags=[], strip=True)
            
            contact_msg = ContactMessage(
                name=escape(name), 
                email=escape(email), 
                message=escape(clean_message)
            )
            db.session.add(contact_msg)
            db.session.commit()
            
            if app.config['MAIL_USERNAME'] and app.config['MAIL_PASSWORD']:
                try:
                    msg = Message(
                        subject=f"New Contact Form Message from {name}",
                        sender=app.config['MAIL_USERNAME'],
                        recipients=[app.config['MAIL_USERNAME']]
                    )
                    
                    msg.body = f"""
New contact form submission from your portfolio website:

Name: {name}
Email: {email}

Message:
{clean_message}

---
Reply directly to: {email}
Sent from: Portfolio Contact Form
                    """
                    
                    mail.send(msg)
                    app.logger.info(f'Contact form email sent successfully to {app.config["MAIL_USERNAME"]}')
                except Exception as email_error:
                    app.logger.error(f'Email sending failed: {repr(email_error)}')
            
            flash(f'Thank you {escape(name)}! Your message has been sent successfully. I\'ll get back to you soon.', 'success')
            return redirect(url_for('home') + '#contact')
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Contact form error: {repr(e)}')
            flash('Sorry, there was an error sending your message. Please try again later.', 'error')
            return redirect(url_for('home') + '#contact')
    
    return redirect(url_for('home') + '#contact')

@app.route('/api/health')
def api_health_check():
    """API health check endpoint for monitoring and load balancers."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'version': '2.0.0'
    })

# ===========================
# AUTHENTICATION FUNCTIONS
# ===========================
def get_serializer():
    """Get URLSafeTimedSerializer instance for password reset tokens"""
    return URLSafeTimedSerializer(app.config['SECRET_KEY'])

def generate_reset_token(email):
    """Generate a secure token for password reset"""
    s = get_serializer()
    return s.dumps(email, salt='password-reset-salt')

def verify_reset_token(token):
    """Verify and decode password reset token"""
    try:
        s = get_serializer()
        # Token expires after 1800 seconds (30 minutes)
        email = s.loads(token, salt='password-reset-salt', max_age=1800)
    except:
        return None  # Token is invalid or expired
    return db.session.execute(db.select(AdminUser).where(AdminUser.email == email)).scalar()

def admin_required(f):
    """Enhanced decorator to require admin authentication with session validation"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if admin is logged in
        if 'admin_logged_in' not in session:
            app.logger.warning(f'Unauthorized access attempt to {request.endpoint} from {request.remote_addr}')
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('admin_login'))
        
        # Check session timeout (30 minutes)
        if 'login_time' in session:
            try:
                login_time = datetime.fromisoformat(session['login_time'])
                if (datetime.now(timezone.utc) - login_time).total_seconds() > 1800:  # 30 minutes
                    session.clear()
                    app.logger.info(f'Session expired for {session.get("admin_email", "unknown")} from {request.remote_addr}')
                    flash('Your session has expired. Please log in again.', 'warning')
                    return redirect(url_for('admin_login'))
            except (ValueError, TypeError):
                # Invalid login_time format, clear session
                session.clear()
                flash('Session invalid. Please log in again.', 'error')
                return redirect(url_for('admin_login'))
        
        # Verify admin still exists in database
        if 'admin_email' in session:
            try:
                admin = db.session.execute(
                    db.select(AdminUser).where(AdminUser.email == session['admin_email'])
                ).scalar()
                if not admin:
                    session.clear()
                    app.logger.warning(f'Admin account no longer exists: {session.get("admin_email")} from {request.remote_addr}')
                    flash('Account no longer valid. Please contact administrator.', 'error')
                    return redirect(url_for('admin_login'))
            except Exception as e:
                app.logger.error(f'Database error during admin verification: {repr(e)}')
                flash('Authentication system error. Please try again.', 'error')
                return redirect(url_for('admin_login'))
        
        return f(*args, **kwargs)
    return decorated_function

# ===========================
# ADMIN AUTHENTICATION ROUTES
# ===========================

@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Stricter rate limiting for login attempts
def admin_login():
    """Admin login page with enhanced security"""
    if 'admin_logged_in' in session:
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()  # Normalize email
        password = request.form.get('password', '').strip()
        
        # Input validation
        if not email or not password:
            app.logger.warning(f'Login attempt with missing credentials from {request.remote_addr}')
            flash('Please enter both email and password.', 'error')
            return render_template('admin_login.html')
        
        # Email format validation
        if '@' not in email or '.' not in email or len(email) > 255:
            app.logger.warning(f'Login attempt with invalid email format: {email} from {request.remote_addr}')
            flash('Invalid email format.', 'error')
            return render_template('admin_login.html')
        
        # Password length validation
        if len(password) < 6 or len(password) > 128:
            app.logger.warning(f'Login attempt with invalid password length from {request.remote_addr}')
            flash('Invalid credentials.', 'error')
            return render_template('admin_login.html')
        
        try:
            admin = db.session.execute(
                db.select(AdminUser).where(AdminUser.email == email)
            ).scalar()
            
            if admin and check_password_hash(admin.password, password):
                # Successful login
                session.permanent = True  # Enable session timeout
                session['admin_logged_in'] = True
                session['admin_email'] = admin.email
                session['login_time'] = datetime.now(timezone.utc).isoformat()
                
                app.logger.info(f'Successful admin login: {email} from {request.remote_addr}')
                flash('Login successful!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                # Failed login - log security event
                app.logger.warning(f'Failed login attempt for email: {email} from {request.remote_addr}')
                flash('Invalid email or password.', 'error')
                
        except Exception as e:
            app.logger.error(f'Login error for {email}: {repr(e)}')
            flash('Login system temporarily unavailable. Please try again later.', 'error')
    
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    """Secure admin logout with session cleanup"""
    admin_email = session.get('admin_email', 'unknown')
    session.clear()  # Clear all session data securely
    
    app.logger.info(f'Admin logout: {admin_email} from {request.remote_addr}')
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('home'))

@app.route('/admin/reset-request', methods=['GET', 'POST'])
@limiter.limit("3 per minute")  # Stricter rate limiting for password reset
def admin_reset_request():
    """Request password reset for admin with enhanced email handling"""
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip().lower()
            
            if not email:
                flash('Please enter your email address.', 'error')
                return render_template('admin_reset_request.html')
            
            # Email format validation
            if '@' not in email or '.' not in email or len(email) > 255:
                flash('Please enter a valid email address.', 'error')
                return render_template('admin_reset_request.html')
            
            # Check if email is configured first
            if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
                app.logger.error('Email not configured - cannot send password reset')
                flash('Email service is not configured. Password reset is currently unavailable.', 'error')
                return render_template('admin_reset_request.html')
            
            admin = db.session.execute(
                db.select(AdminUser).where(AdminUser.email == email)
            ).scalar()
            
            # Always show success message for security (prevent email enumeration)
            success_message = 'If an account with that email exists, a reset link has been sent. Please check your email (including spam folder).'
            
            if admin:
                try:
                    # Test email configuration by creating a simple message first
                    app.logger.info(f'Attempting to send password reset email to {admin.email}')
                    
                    token = generate_reset_token(admin.email)
                    reset_url = url_for('admin_reset_password', token=token, _external=True)
                    
                    # Create message with minimal content to avoid encoding issues
                    msg = Message(
                        subject='Password Reset Request',
                        sender=app.config['MAIL_USERNAME'],
                        recipients=[admin.email]
                    )
                    
                    msg.body = f'''Password Reset Request

Click this link to reset your password:
{reset_url}

This link expires in 30 minutes.

If you did not request this, ignore this email.'''
                    
                    # Send the email
                    mail.send(msg)
                    app.logger.info(f'Password reset email sent successfully to {admin.email}')
                    
                except Exception as e:
                    app.logger.error(f'Password reset email failed for {admin.email}: {str(e)}')
                    # For debugging, show the actual error in development
                    if app.config.get('FLASK_ENV') == 'development':
                        flash(f'Email sending failed: {str(e)}', 'error')
                        return render_template('admin_reset_request.html')
            else:
                app.logger.warning(f'Password reset attempted for non-existent email: {email}')
            
            flash(success_message, 'info')
            return redirect(url_for('admin_login'))
            
        except Exception as e:
            app.logger.error(f'Password reset request error: {str(e)}')
            flash(f'An error occurred: {str(e)}', 'error')
            return render_template('admin_reset_request.html')
    
    return render_template('admin_reset_request.html')

@app.route('/admin/reset-password/<token>', methods=['GET', 'POST'])
def admin_reset_password(token):
    """Reset admin password using token"""
    admin = verify_reset_token(token)
    if admin is None:
        flash('That token is invalid or has expired.', 'error')
        return redirect(url_for('admin_reset_request'))
    
    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        if not password or len(password) < 12:
            flash('Password must be at least 12 characters long for security.', 'error')
            return render_template('admin_reset_password.html')
        
        # Enhanced password validation
        if not any(c.isupper() for c in password):
            flash('Password must contain at least one uppercase letter.', 'error')
            return render_template('admin_reset_password.html')
        
        if not any(c.islower() for c in password):
            flash('Password must contain at least one lowercase letter.', 'error')
            return render_template('admin_reset_password.html')
        
        if not any(c.isdigit() for c in password):
            flash('Password must contain at least one number.', 'error')
            return render_template('admin_reset_password.html')
        
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            flash('Password must contain at least one special character.', 'error')
            return render_template('admin_reset_password.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('admin_reset_password.html')
        
        # Update password with enhanced hashing
        admin.password = generate_password_hash(
            password, 
            method='pbkdf2:sha256', 
            salt_length=16  # Increased salt length for better security
        )
        db.session.commit()
        
        app.logger.info(f'Password reset completed for admin: {admin.email} from {request.remote_addr}')
        flash('Your password has been updated successfully! You can now log in with your new password.', 'success')
        return redirect(url_for('admin_login'))
    
    return render_template('admin_reset_password.html')
@app.route('/admin/messages')
@admin_required
def view_messages():
    """Admin route to view all contact messages from database"""
    try:
        messages = db.session.execute(
            db.select(ContactMessage).order_by(ContactMessage.created_at.desc())
        ).scalars().all()
        
        return render_template('admin_messages.html', 
                             messages=messages,
                             contact_info=ContactInfo.query.first(),
                             current_year=datetime.now().year)
    except Exception as e:
        app.logger.error(f'Error fetching messages: {repr(e)}')
        flash('Error loading messages.', 'error')
        return redirect(url_for('home'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard with portfolio management"""
    projects = Project.query.all()
    experience = Experience.query.all()
    certifications = Certification.query.all()
    skills = Skill.query.all()
    contact_info = ContactInfo.query.first()
    
    return render_template('admin_dashboard.html',
                         projects=projects,
                         experience=experience,
                         certifications=certifications,
                         skills=skills,
                         contact_info=contact_info,
                         current_year=datetime.now().year)

# Project Management Routes
@app.route('/admin/projects/add', methods=['GET', 'POST'])
@admin_required
def add_project():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        technologies = request.form.get('technologies', '').split(',')
        github_url = request.form.get('github_url')
        has_demo = bool(request.form.get('has_demo'))
        demo_url = request.form.get('demo_url') if has_demo else None
        categories = request.form.getlist('categories')
        
        if not categories:
            flash('Please select at least one category.', 'error')
            return render_template('admin_project_form.html', project=None)
        
        project = Project(
            title=title,
            description=description,
            github_url=github_url,
            demo_url=demo_url,
            has_demo=has_demo
        )
        project.set_technologies([tech.strip() for tech in technologies if tech.strip()])
        project.set_categories(categories)
        
        db.session.add(project)
        db.session.commit()
        flash('Project added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_project_form.html', project=None)

@app.route('/admin/projects/<int:project_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_project(project_id):
    project = Project.query.get_or_404(project_id)
    
    if request.method == 'POST':
        project.title = request.form.get('title')
        project.description = request.form.get('description')
        technologies = request.form.get('technologies', '').split(',')
        project.set_technologies([tech.strip() for tech in technologies if tech.strip()])
        project.github_url = request.form.get('github_url')
        project.has_demo = bool(request.form.get('has_demo'))
        project.demo_url = request.form.get('demo_url') if project.has_demo else None
        categories = request.form.getlist('categories')
        
        if not categories:
            flash('Please select at least one category.', 'error')
            return render_template('admin_project_form.html', project=project)
        
        project.set_categories(categories)
        
        db.session.commit()
        flash('Project updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_project_form.html', project=project)

@app.route('/admin/projects/<int:project_id>/delete', methods=['POST'])
@admin_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    db.session.delete(project)
    db.session.commit()
    flash('Project deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

# Experience Management Routes
@app.route('/admin/experience/add', methods=['GET', 'POST'])
@admin_required
def add_experience():
    if request.method == 'POST':
        title = request.form.get('title')
        company = request.form.get('company')
        period = request.form.get('period')
        description = request.form.get('description')
        achievements = request.form.get('achievements', '').split('\n')
        
        exp = Experience(
            title=title,
            company=company,
            period=period,
            description=description
        )
        exp.set_achievements([ach.strip() for ach in achievements if ach.strip()])
        
        db.session.add(exp)
        db.session.commit()
        flash('Experience added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_experience_form.html', experience=None)

@app.route('/admin/experience/<int:exp_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_experience(exp_id):
    exp = Experience.query.get_or_404(exp_id)
    
    if request.method == 'POST':
        exp.title = request.form.get('title')
        exp.company = request.form.get('company')
        exp.period = request.form.get('period')
        exp.description = request.form.get('description')
        achievements = request.form.get('achievements', '').split('\n')
        exp.set_achievements([ach.strip() for ach in achievements if ach.strip()])
        
        db.session.commit()
        flash('Experience updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_experience_form.html', experience=exp)
    
@app.route('/admin/experience/<int:exp_id>/delete', methods=['POST'])
@admin_required
def delete_experience(exp_id):
    exp = Experience.query.get_or_404(exp_id)
    db.session.delete(exp)
    db.session.commit()
    flash('Experience deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

# Certification Management Routes
@app.route('/admin/certifications/add', methods=['GET', 'POST'])
@admin_required
def add_certification():
    if request.method == 'POST':
        name = request.form.get('name')
        issuer = request.form.get('issuer')
        date = request.form.get('date')
        badge_url = request.form.get('badge_url')
        
        cert = Certification(
            name=name,
            issuer=issuer,
            date=date,
            badge_url=badge_url
        )
        
        db.session.add(cert)
        db.session.commit()
        flash('Certification added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_certification_form.html', certification=None)

@app.route('/admin/certifications/<int:cert_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_certification(cert_id):
    cert = Certification.query.get_or_404(cert_id)
    
    if request.method == 'POST':
        cert.name = request.form.get('name')
        cert.issuer = request.form.get('issuer')
        cert.date = request.form.get('date')
        cert.badge_url = request.form.get('badge_url')
        
        db.session.commit()
        flash('Certification updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_certification_form.html', certification=cert)

@app.route('/admin/certifications/<int:cert_id>/delete', methods=['POST'])
@admin_required
def delete_certification(cert_id):
    cert = Certification.query.get_or_404(cert_id)
    db.session.delete(cert)
    db.session.commit()
    flash('Certification deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

# Skill Management Routes
@app.route('/admin/skills/add', methods=['GET', 'POST'])
@admin_required
def add_skill():
    if request.method == 'POST':
        category = request.form.get('category')
        items = request.form.get('items', '').split(',')
        level = int(request.form.get('level', 0))
        
        skill = Skill(
            category=category,
            level=level
        )
        skill.set_items([item.strip() for item in items if item.strip()])
        
        db.session.add(skill)
        db.session.commit()
        flash('Skill added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_skill_form.html', skill=None)

@app.route('/admin/skills/<int:skill_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_skill(skill_id):
    skill = Skill.query.get_or_404(skill_id)
    
    if request.method == 'POST':
        skill.category = request.form.get('category')
        items = request.form.get('items', '').split(',')
        skill.set_items([item.strip() for item in items if item.strip()])
        skill.level = int(request.form.get('level', 0))
        
        db.session.commit()
        flash('Skill updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_skill_form.html', skill=skill)

@app.route('/admin/skills/<int:skill_id>/delete', methods=['POST'])
@admin_required
def delete_skill(skill_id):
    skill = Skill.query.get_or_404(skill_id)
    db.session.delete(skill)
    db.session.commit()
    flash('Skill deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

# Contact Info Management
@app.route('/admin/contact/edit', methods=['GET', 'POST'])
@admin_required
def edit_contact_info():
    contact_info = ContactInfo.query.first()
    if not contact_info:
        contact_info = ContactInfo()
    
    if request.method == 'POST':
        contact_info.email = request.form.get('email')
        contact_info.phone = request.form.get('phone')
        contact_info.linkedin = request.form.get('linkedin')
        contact_info.github = request.form.get('github')
        contact_info.location = request.form.get('location')
        
        if not ContactInfo.query.first():
            db.session.add(contact_info)
        
        db.session.commit()
        flash('Contact info updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_contact_form.html', contact_info=contact_info)

@app.route('/admin/messages/<int:message_id>/mark-read')
@admin_required
def mark_message_read(message_id):
    """Mark a message as read"""
    try:
        message = db.get_or_404(ContactMessage, message_id)
        message.is_read = True
        db.session.commit()
        flash('Message marked as read.', 'success')
    except Exception as e:
        app.logger.error(f'Error marking message as read: {repr(e)}')
        flash('Error updating message.', 'error')
    return redirect(url_for('view_messages'))
def sitemap():
    """Generate dynamic sitemap for SEO optimization."""
    try:
        # Get current date for lastmod
        current_date = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        
        # Define pages with dynamic lastmod dates
        pages = [
            {'url': url_for('home', _external=True), 'lastmod': current_date},
            {'url': url_for('all_projects', _external=True), 'lastmod': current_date},
            {'url': url_for('experience', _external=True), 'lastmod': current_date},
        ]
        
        # Generate sitemap XML inline to avoid template dependency
        sitemap_xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
        sitemap_xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        
        for page in pages:
            sitemap_xml += f'  <url>\n'
            sitemap_xml += f'    <loc>{page["url"]}</loc>\n'
            sitemap_xml += f'    <lastmod>{page["lastmod"]}</lastmod>\n'
            sitemap_xml += f'    <changefreq>weekly</changefreq>\n'
            sitemap_xml += f'    <priority>0.8</priority>\n'
            sitemap_xml += f'  </url>\n'
        
        sitemap_xml += '</urlset>'
        
        response = app.response_class(sitemap_xml, mimetype='application/xml')
        return response
        
    except Exception as e:
        app.logger.error(f'Sitemap generation error: {repr(e)}')
        return 'Sitemap generation failed', 500

# ===========================
# ERROR HANDLERS
# ===========================

@app.errorhandler(404)
def not_found(error):
    """Custom 404 error handler."""
    contact_info = ContactInfo.query.first()
    return render_template('404.html', 
                         contact_info=contact_info,
                         current_year=datetime.now().year), 404

@app.errorhandler(500)
def internal_error(error):
    """Custom 500 error handler with safe fallback."""
    app.logger.error(f'Server Error: {repr(error)}')
    try:
        contact_info = ContactInfo.query.first()
        return render_template('500.html', 
                             contact_info=contact_info,
                             current_year=datetime.now().year), 500
    except Exception as e:
        app.logger.error(f'Error handler failed: {repr(e)}')
        # Fallback to simple HTML response if template fails
        return '''<!DOCTYPE html>
<html><head><title>Server Error</title></head>
<body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
<h1>500 - Server Error</h1>
<p>Something went wrong. Please try again later.</p>
<a href="/">Go Home</a>
</body></html>''', 500

@app.errorhandler(403)
def forbidden(error):
    """Custom 403 error handler."""
    contact_info = ContactInfo.query.first()
    return render_template('403.html', 
                         contact_info=contact_info,
                         current_year=datetime.now().year), 403

# Create all database tables when app starts
with app.app_context():
    try:
        db.create_all()
        from models import create_default_admin, seed_initial_data
        create_default_admin()
        seed_initial_data()
        app.logger.info('Database tables created successfully')
    except Exception as e:
        app.logger.error(f'Database initialization error: {repr(e)}')

# ===========================
# RUN THE APPLICATION
# ===========================
if __name__ == "__main__":
    # Parse environment variables with error handling
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Parse port with error handling
    try:
        port = int(os.environ.get('PORT', 3000))
        if port < 1 or port > 65535:
            raise ValueError("Port must be between 1 and 65535")
    except (ValueError, TypeError) as e:
        app.logger.warning(f'Invalid PORT environment variable: {e}, using default port 3000')
        port = 3000
    
    # Security: Use localhost for development, allow override for production
    is_production = os.environ.get('FLASK_ENV') == 'production'
    host = os.environ.get('HOST', '127.0.0.1' if not is_production else '0.0.0.0')
    
    # Security warning for 0.0.0.0 binding
    if host == '0.0.0.0':
        app.logger.warning('Running on 0.0.0.0 - ensure proper firewall and security measures are in place')
    
    # Start the application
    app.run(debug=debug_mode, host=host, port=port)