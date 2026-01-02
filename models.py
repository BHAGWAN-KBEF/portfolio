from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash
import json

db = SQLAlchemy()

class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_read = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<ContactMessage {self.name}>'

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    technologies = db.Column(db.Text)  # JSON string
    github_url = db.Column(db.String(500))
    demo_url = db.Column(db.String(500))
    has_demo = db.Column(db.Boolean, default=False)
    categories = db.Column(db.Text)  # JSON string for multiple categories
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def get_technologies(self):
        return json.loads(self.technologies) if self.technologies else []
    
    def set_technologies(self, tech_list):
        self.technologies = json.dumps(tech_list)
    
    def get_categories(self):
        return json.loads(self.categories) if self.categories else []
    
    def set_categories(self, category_list):
        self.categories = json.dumps(category_list)
    
    @property
    def category(self):
        # For backward compatibility, return first category
        cats = self.get_categories()
        return cats[0] if cats else 'python'

class Experience(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    company = db.Column(db.String(200), nullable=False)
    period = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    achievements = db.Column(db.Text)  # JSON string
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def get_achievements(self):
        return json.loads(self.achievements) if self.achievements else []
    
    def set_achievements(self, achievement_list):
        self.achievements = json.dumps(achievement_list)

class Certification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    issuer = db.Column(db.String(200), nullable=False)
    date = db.Column(db.String(50), nullable=False)
    badge_url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Skill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False)
    items = db.Column(db.Text)  # JSON string
    level = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def get_items(self):
        return json.loads(self.items) if self.items else []
    
    def set_items(self, item_list):
        self.items = json.dumps(item_list)

class ContactInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(50))
    linkedin = db.Column(db.String(500))
    github = db.Column(db.String(500))
    location = db.Column(db.String(200))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(200), unique=True, nullable=False)
    content = db.Column(db.Text, nullable=False)
    excerpt = db.Column(db.String(300))
    published = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<BlogPost {self.title}>'

class AdminUser(db.Model):
    """Model for admin users who can access the admin panel"""
    __tablename__ = "admin_users"
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Hashed password
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<AdminUser {self.email}>'

def create_default_admin():
    """Create default admin user with enhanced security if none exists"""
    try:
        if not AdminUser.query.first():
            default_email = "baffouremmanuel1997@gmail.com"
            default_password = "Admin@2025!Secure"  # Strong default password
            
            admin = AdminUser(
                email=default_email,
                password=generate_password_hash(
                    default_password, 
                    method='pbkdf2:sha256', 
                    salt_length=16  # Enhanced salt length
                )
            )
            db.session.add(admin)
            db.session.commit()
            print(f"Default admin created: {default_email}")
            print(f"IMPORTANT: Change default password immediately!")
            print(f"Default password: {default_password}")
    except Exception as e:
        print(f"Error creating default admin: {e}")

def seed_initial_data():
    """Seed database with initial portfolio data"""
    try:
        # Contact Info
        if not ContactInfo.query.first():
            contact = ContactInfo(
                email='baffouremmanuel1997@gmail.com',
                phone='+233202062877',
                linkedin='https://www.linkedin.com/in/emmanuelfrimpongkyei-baffour/',
                github='https://github.com/BHAGWAN-KBEF',
                location='Kumasi, Ghana'
            )
            db.session.add(contact)
        
        # Skills
        if not Skill.query.first():
            skills_data = [
                {'category': 'cloud', 'items': ['AWS EC2', 'AWS S3', 'AWS Lambda', 'AWS RDS', 'AWS CloudFormation', 'AWS ECS'], 'level': 90},
                {'category': 'devops', 'items': ['Docker', 'Kubernetes', 'Jenkins', 'GitHub Actions', 'Terraform', 'Ansible'], 'level': 95},
                {'category': 'programming', 'items': ['Python', 'Flask', 'Bash Scripting', 'YAML', 'JSON'], 'level': 85},
                {'category': 'monitoring', 'items': ['Prometheus', 'Grafana', 'ELK Stack', 'CloudWatch', 'Datadog'], 'level': 88}
            ]
            for skill_data in skills_data:
                skill = Skill(category=skill_data['category'], level=skill_data['level'])
                skill.set_items(skill_data['items'])
                db.session.add(skill)
        
        # Experience
        if not Experience.query.first():
            exp = Experience(
                title='Cloud & DevOps Engineer',
                company='GETINNOTIZED GmbH',
                period='October 2025 - Present',
                description='Leading DevOps transformation initiatives for a German technology company, implementing standardized workflows, CI/CD pipelines, and containerization strategies.'
            )
            achievements = [
                'Implemented standardized workflows with Conventional Commits and pre-commit hooks, improving team delivery efficiency by 50%',
                'Engineered CI/CD pipelines using GitHub Actions with comprehensive testing and security scans, increasing deployment reliability by 60%',
                'Developed multi-stage Dockerfiles and Docker Compose environments, reducing build times by 1 hour and onboarding time by 70%',
                'Authored comprehensive documentation and governance standards, accelerating team ramp-up by 40%',
                'Integrated pytest with 80%+ coverage thresholds and automated test reporting in CI/CD workflows',
                'Established branch protection rules and security scanning with Bandit for enhanced code quality'
            ]
            exp.set_achievements(achievements)
            db.session.add(exp)
        
        # Certifications
        if not Certification.query.first():
            certs = [
                {'name': 'AWS Certified Solutions Architect - Associate', 'issuer': 'Amazon Web Services', 'date': '2025', 'badge_url': '#'},
                {'name': 'Microsoft Security, Compliance & Identity Fundamentals', 'issuer': 'Microsoft', 'date': '2025', 'badge_url': '#'},
                {'name': 'ISC2 Certified in Cybersecurity', 'issuer': 'ISC2', 'date': '2024', 'badge_url': '#'}
            ]
            for cert_data in certs:
                cert = Certification(**cert_data)
                db.session.add(cert)
        
        # Projects
        if not Project.query.first():
            projects = [
                {
                    'title': 'Event-Driven Order Service',
                    'description': 'Production-ready, serverless event-driven order processing system built on AWS using Terraform. Features API Gateway, Lambda, SQS, DynamoDB with comprehensive monitoring and CI/CD.',
                    'technologies': ['AWS', 'Terraform', 'Lambda', 'API Gateway', 'SQS', 'DynamoDB', 'CloudWatch', 'Python'],
                    'github_url': 'https://github.com/BHAGWAN-KBEF/aws-serverless-order-platform',
                    'categories': ['aws', 'devops'],
                    'has_demo': False
                },
                {
                    'title': 'VProfile - Enterprise Java CI/CD Pipeline',
                    'description': 'Multi-tier Java web application with comprehensive GitLab CI/CD pipeline featuring automated testing, security scanning, Docker containerization, and deployment automation.',
                    'technologies': ['GitLab CI/CD', 'Docker', 'Java', 'Maven', 'Trivy', 'Spring Boot', 'MySQL', 'Ansible'],
                    'github_url': 'https://gitlab.com/hkh-group4794951/vprofile',
                    'category': 'devops'
                },
                {
                    'title': 'Flask Blog with User Authentication',
                    'description': 'Full-featured blog application with user registration, authentication, commenting system, and admin controls. Features rich text editor and responsive Bootstrap design.',
                    'technologies': ['Python', 'Flask', 'SQLAlchemy', 'Bootstrap', 'CKEditor', 'SQLite', 'WTForms'],
                    'github_url': 'https://github.com/BHAGWAN-KBEF/blog-website-day-70',
                    'demo_url': 'https://web-production-0901.up.railway.app/',
                    'category': 'python'
                },
                {
                    'title': 'AWS Translate Capstone Project',
                    'description': 'Fully serverless, multi-language translation application powered by AWS Translate, Lambda, S3, and API Gateway. Features real-time translation between 5 languages with responsive UI.',
                    'technologies': ['AWS', 'Lambda', 'S3', 'API Gateway', 'Translate', 'JavaScript', 'HTML/CSS'],
                    'github_url': 'https://github.com/BHAGWAN-KBEF/aws-translate-capstone',
                    'category': 'aws'
                },
                {
                    'title': 'Portfolio Website - Python Flask',
                    'description': 'Modern, responsive portfolio website built with Python Flask, featuring dark/light theme, contact form, admin panel, and secure authentication system.',
                    'technologies': ['Python', 'Flask', 'SQLAlchemy', 'Tailwind CSS', 'JavaScript', 'SQLite'],
                    'github_url': 'https://github.com/BHAGWAN-KBEF/portfolio',
                    'demo_url': 'https://your-portfolio-demo.com',
                    'category': 'python'
                },
                {
                    'title': 'EventAnnouncer - Serverless Event Management',
                    'description': 'Serverless web application for event announcements with automatic email notifications. Features event creation, subscription management, and AWS SNS integration for instant alerts.',
                    'technologies': ['AWS', 'Lambda', 'API Gateway', 'SNS', 'S3', 'Python', 'Terraform', 'JavaScript'],
                    'github_url': 'https://github.com/BHAGWAN-KBEF/eventannouncer-serverless',
                    'category': 'aws'
                },
                {
                    'title': 'Microservice DevOps Pipeline',
                    'description': 'Production-ready Node.js microservice with complete DevOps pipeline featuring Docker, GitHub Actions CI/CD, Terraform, Kubernetes, ArgoCD GitOps, and Prometheus monitoring.',
                    'technologies': ['Node.js', 'Docker', 'Kubernetes', 'Terraform', 'ArgoCD', 'Prometheus', 'GitHub Actions', 'AWS EKS'],
                    'github_url': 'https://github.com/BHAGWAN-KBEF/microservice-devops-pipeline',
                    'category': 'devops'
                },
                {
                    'title': 'CI/CD Pipeline with Jenkins',
                    'description': 'Automated deployment pipeline with comprehensive testing, security scanning, and multi-environment deployment strategies.',
                    'technologies': ['Jenkins', 'Docker', 'Python', 'AWS', 'SonarQube'],
                    'github_url': 'https://github.com/BHAGWAN-KBEF/java-webapp-cicd-automation',
                    'category': 'devops'
                },
                {
                    'title': 'Python Flask API with Authentication',
                    'description': 'Production-ready RESTful API with JWT authentication, rate limiting, and comprehensive testing suite.',
                    'technologies': ['Python', 'Flask', 'PostgreSQL', 'JWT', 'Redis', 'Pytest'],
                    'github_url': 'https://github.com/BHAGWAN-KBEF/flask-api-auth',
                    'demo_url': 'https://flask-api-demo.herokuapp.com',
                    'category': 'python'
                }
            ]
            for proj_data in projects:
                project = Project(
                    title=proj_data['title'],
                    description=proj_data['description'],
                    github_url=proj_data['github_url'],
                    demo_url=proj_data.get('demo_url'),
                    has_demo=proj_data.get('has_demo', bool(proj_data.get('demo_url')))
                )
                project.set_technologies(proj_data['technologies'])
                project.set_categories(proj_data.get('categories', [proj_data.get('category', 'python')]))
                db.session.add(project)
        
        db.session.commit()
        print("Initial data seeded successfully")
    except Exception as e:
        print(f"Error seeding data: {e}")
        db.session.rollback()