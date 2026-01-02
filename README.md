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

## 📁 Project Structure

```
portfolio/
├── main.py                    # Main Flask application
├── models.py                  # Database models and seeding
├── requirements.txt           # Python dependencies
├── LICENSE                    # MIT License
├── README.md                  # Project documentation
├── .env                       # Environment variables (create this)
├── templates/                 # Jinja2 templates
│   ├── base.html             # Base template
│   ├── header.html           # Navigation header
│   ├── footer.html           # Footer component
│   ├── index.html            # Homepage
│   ├── projects.html         # Projects showcase
│   ├── experience.html       # Professional experience
│   ├── admin_dashboard.html  # Admin main panel
│   ├── admin_login.html      # Admin authentication
│   └── admin_*_form.html     # Admin CRUD forms
├── static/                   # Static assets
│   ├── css/
│   │   └── style.css        # Custom styles
│   ├── js/
│   │   └── main.js          # JavaScript functionality
│   ├── images/
│   │   └── profile.png      # Profile image
│   └── documents/
│       └── Emmanuel_Frimpong_CV.pdf  # Resume file
└── instance/
    └── portfolio.db          # SQLite database (auto-created)
```

## 🚀 Quick Start

### Prerequisites
- **Python 3.13+** (or 3.8+)
- **pip** (Python package installer)
- **Git** (for version control)

### Installation & Setup

1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd portfolio
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
   # Create .env file for email configuration
   MAIL_USERNAME=your-email@gmail.com
   MAIL_PASSWORD=your-app-password
   SECRET_KEY=your-secret-key
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

## 🎨 Content Management

### Adding Projects
1. Login to admin panel
2. Navigate to Projects section
3. Click "Add Project"
4. Fill in:
   - Project title and description
   - Technologies used (comma-separated)
   - GitHub repository URL
   - Categories (Python, AWS, DevOps - multiple selection)
   - Demo URL (optional)

### Managing Experience
- Add professional positions
- Include achievements and responsibilities
- Timeline automatically organized

### Certifications & Skills
- Professional credentials with issuer and date
- Skills organized by categories with proficiency levels
- Automatic display on homepage and experience page

## 🚀 Deployment

### Environment Variables for Production
```bash
DATABASE_URL=postgresql://user:password@host:port/database
FLASK_ENV=production
SECRET_KEY=your-production-secret-key
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
```

### Deployment Platforms

#### Render (Recommended)
1. Create `Procfile`:
   ```
   web: gunicorn main:app --bind 0.0.0.0:$PORT
   ```
2. Push to GitHub repository
3. Connect GitHub repo to Render
4. Add PostgreSQL database
5. Set environment variables
6. Deploy automatically

#### Heroku
1. Create `Procfile`:
   ```
   web: gunicorn main:app
   ```
2. Add PostgreSQL addon
3. Set environment variables
4. Deploy with Git

#### Railway
1. Connect GitHub repository
2. Add PostgreSQL service
3. Set environment variables
4. Auto-deploy on push

#### DigitalOcean App Platform
1. Connect repository
2. Configure build settings
3. Add managed PostgreSQL database
4. Set environment variables

### Database Migration
- **Development**: Uses SQLite (automatic)
- **Production**: Uses PostgreSQL (set DATABASE_URL)
- **Auto-migration**: Database tables created automatically
- **Data seeding**: Initial portfolio data populated on first run

## 🔧 Customization

### Updating Personal Information
Use the admin panel to update:
- Contact information
- Professional experience
- Skills and certifications
- Project portfolio

### Styling Customization
- **Colors**: Modify Tailwind classes in templates
- **Layout**: Edit templates in `templates/` directory
- **Custom CSS**: Add styles to `static/css/style.css`
- **JavaScript**: Enhance functionality in `static/js/main.js`

## 📧 Email Configuration

### Gmail Setup
1. Enable 2-factor authentication
2. Generate app password
3. Set environment variables:
   ```bash
   MAIL_USERNAME=your-email@gmail.com
   MAIL_PASSWORD=your-16-digit-app-password
   ```

### Contact Form Features
- Form validation and sanitization
- Email notifications to admin
- Message storage in database
- Admin panel for message management

## 🛡️ Security Features

- **CSRF Protection** - All forms protected
- **Rate Limiting** - Prevents brute force attacks
- **Password Hashing** - Secure admin authentication
- **Input Sanitization** - XSS prevention
- **Security Headers** - Comprehensive protection
- **Session Management** - Secure admin sessions

## 📱 Browser Support

- ✅ Chrome (latest)
- ✅ Firefox (latest)
- ✅ Safari (latest)
- ✅ Edge (latest)
- ✅ Mobile browsers (iOS Safari, Chrome Mobile)

## 🆘 Troubleshooting

### Common Issues

**Database Errors**
```bash
# Delete database to recreate with new schema
rm instance/portfolio.db  # Linux/Mac
del instance\portfolio.db  # Windows
```

**Port Already in Use**
```bash
# Kill existing Python processes
taskkill /F /IM python.exe  # Windows
pkill python                # Linux/Mac
```

**Dependencies Issues**
```bash
# Upgrade pip and reinstall
python -m pip install --upgrade pip
pip install -r requirements.txt --force-reinstall
```

**Email Not Working**
- Check Gmail app password setup
- Verify environment variables
- Check firewall/network settings

## 📄 License

This project is protected under **All Rights Reserved** copyright - see the [LICENSE](LICENSE) file for details.

### Copyright Protection
```
Copyright (c) 2026 Kyei-Baffour Emmanuel Frimpong. All Rights Reserved.

This portfolio and its contents are protected by copyright law.
Unauthorized copying, distribution, or use is strictly prohibited.
```

**Permitted**: Viewing for hiring/collaboration evaluation
**Prohibited**: Copying, modifying, distributing, or commercial useermit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## ✅ Production Readiness Checklist

- ✅ **Database**: PostgreSQL support configured
- ✅ **Security**: CSRF, rate limiting, authentication implemented
- ✅ **Admin Panel**: Complete content management system
- ✅ **Responsive**: Mobile-optimized design
- ✅ **SEO**: Meta tags and semantic HTML
- ✅ **Performance**: Optimized assets and queries
- ✅ **Error Handling**: Custom error pages
- ✅ **Logging**: Application logging configured
- ✅ **Environment**: Production/development configurations
- ✅ **Documentation**: Comprehensive setup and usage guide

---

**Built with ❤️ by Kyei-Baffour Emmanuel Frimpong**

*DevOps Engineer | AWS Cloud Specialist | Python Developer*

**© 2026 Kyei-Baffour Emmanuel Frimpong - All Rights Reserved**