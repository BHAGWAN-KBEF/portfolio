# Portfolio Website - DevOps & Cloud Engineer

**Copyright (c) 2026 Kyei-Baffour Emmanuel Frimpong. All rights reserved.**

A modern, responsive portfolio website built with Python Flask, featuring database-driven content management and secure admin panel for showcasing DevOps and Cloud Engineering expertise.

## 🚀 Key Features

- **🎛️ Admin Dashboard** - Complete CRUD operations for all portfolio content
- **📊 Database-Driven** - Dynamic content management with PostgreSQL support
- **🔒 Secure Authentication** - Protected admin panel with CSRF protection and rate limiting
- **📱 Responsive Design** - Mobile-first approach with Tailwind CSS
- **🌙 Dark/Light Theme** - Toggle between themes with localStorage persistence
- **📧 Contact System** - Functional contact form with email notifications
- **🎨 Project Showcase** - Dynamic project display with multiple categories and filtering
- **⚡ Performance Optimized** - Fast loading with optimized assets
- **🔍 SEO Ready** - Proper meta tags and semantic HTML

## 🛠️ Technology Stack

### Backend
- **Python 3.13+** - Modern Python version
- **Flask 3.0.3** - Lightweight web framework
- **SQLAlchemy 1.4.53** - Database ORM
- **PostgreSQL/SQLite** - Production/Development databases
- **Flask-WTF** - CSRF protection and form handling
- **Flask-Limiter** - Rate limiting for security
- **Flask-Mail** - Email functionality

### Frontend
- **Tailwind CSS** - Utility-first CSS framework
- **Vanilla JavaScript** - No heavy frameworks, optimized performance
- **Jinja2 Templates** - Server-side rendering
- **Responsive Design** - Mobile-first approach

### Security & Production
- **CSRF Protection** - Cross-site request forgery prevention
- **Rate Limiting** - DDoS protection
- **Password Hashing** - Secure admin authentication
- **Security Headers** - XSS, clickjacking protection
- **Environment Variables** - Secure configuration management

## 🚀 Quick Start

### Prerequisites
- **Python 3.13+** (or 3.8+)
- **pip** (Python package installer)
- **Git** (for version control)

### Installation & Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/devops-portfolio-pro.git
   cd devops-portfolio-pro
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   
   # Activate virtual environment
   venv\Scripts\activate     # Windows
   source venv/bin/activate  # Linux/Mac
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Create environment file** (optional)
   ```bash
   # Copy example and fill in your values
   cp .env.example .env
   ```

5. **Run the application**
   ```bash
   python main.py
   ```

6. **Access the website**
   - **Portfolio**: `http://127.0.0.1:3000`
   - **Admin Panel**: `http://127.0.0.1:3000/admin/login`

## 🔐 Admin Access

### Default Credentials
- **Email**: `baffouremmanuel1997@gmail.com`
- **Password**: `Admin@2025!Secure`
- **URL**: `/admin/login`

⚠️ **IMPORTANT**: Change the default password immediately after first login!

### Admin Features
- ✅ **Projects Management** - Add, edit, delete projects with multiple categories
- ✅ **Experience Management** - Manage professional timeline and achievements
- ✅ **Certifications** - Add and manage professional credentials
- ✅ **Skills Management** - Organize skills by category with proficiency levels
- ✅ **Contact Info** - Update personal contact information
- ✅ **Messages** - View and manage contact form submissions

## 🚀 Deployment

### Environment Variables for Production
```bash
DATABASE_URL=postgresql://user:password@host:port/database
FLASK_ENV=production
SECRET_KEY=your-production-secret-key
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
```

### Render Deployment (Recommended)

1. **Push to GitHub**
   ```bash
   git init
   git add .
   git commit -m "Professional DevOps Portfolio - Production Ready"
   git branch -M main
   git remote add origin https://github.com/yourusername/devops-portfolio-pro.git
   git push -u origin main
   ```

2. **Deploy on Render**
   - Go to [render.com](https://render.com) → Sign up/Login
   - Click **"New +"** → **"Web Service"**
   - Connect GitHub → Select your repository
   - Configure:
     - **Name**: `devops-portfolio-pro`
     - **Environment**: `Python 3`
     - **Build Command**: `pip install -r requirements.txt`
     - **Start Command**: `gunicorn main:app`

3. **Add PostgreSQL Database**
   - Click **"New +"** → **"PostgreSQL"**
   - **Name**: `portfolio-database`
   - Copy the Database URL

4. **Set Environment Variables**
   ```
   DATABASE_URL=<your-postgresql-url>
   FLASK_ENV=production
   SECRET_KEY=<generate-random-key>
   MAIL_USERNAME=baffouremmanuel1997@gmail.com
   MAIL_PASSWORD=<your-gmail-app-password>
   ```

5. **Deploy** → Your site will be live at: `https://devops-portfolio-pro.onrender.com`

## 📧 Email Configuration

### Gmail Setup
1. Enable 2-factor authentication
2. Generate app password
3. Set environment variables:
   ```bash
   MAIL_USERNAME=your-email@gmail.com
   MAIL_PASSWORD=your-16-digit-app-password
   ```

## 🛡️ Security Features

- **CSRF Protection** - All forms protected
- **Rate Limiting** - Prevents brute force attacks
- **Password Hashing** - PBKDF2-SHA256 with 16-byte salt
- **Input Sanitization** - XSS prevention
- **Security Headers** - Comprehensive protection
- **Session Management** - 30-minute timeout with secure cookies

## 🆘 Troubleshooting

### Common Issues

**Port Already in Use**
```bash
taskkill /F /IM python.exe  # Windows
pkill python                # Linux/Mac
```

**Database Errors**
```bash
# Delete database to recreate with new schema
del instance\portfolio.db  # Windows
rm instance/portfolio.db   # Linux/Mac
```

**Dependencies Issues**
```bash
pip install -r requirements.txt --force-reinstall
```

## 📄 License

This project is protected under **All Rights Reserved** copyright - see the [LICENSE](LICENSE) file for details.

### Copyright Protection
```
Copyright (c) 2026 Kyei-Baffour Emmanuel Frimpong. All Rights Reserved.

This portfolio and its contents are protected by copyright law.
Unauthorized copying, distribution, or use is strictly prohibited.
```

**Permitted**: Viewing for hiring/collaboration evaluation  
**Prohibited**: Copying, modifying, distributing, or commercial use

---

**Built with ❤️ by Kyei-Baffour Emmanuel Frimpong**

*DevOps Engineer | AWS Cloud Specialist | Python Developer*

**© 2026 Kyei-Baffour Emmanuel Frimpong - All Rights Reserved**