#!/usr/bin/env python3
"""
Script to create a default admin user for the threat intelligence system.
"""

import os
import sys
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def create_default_user():
    """Create a default admin user."""
    
    # Get the absolute path to the instance directory
    base_dir = os.path.dirname(os.path.abspath(__file__))
    instance_dir = os.path.join(base_dir, 'instance')
    db_path = os.path.join(instance_dir, 'threat_intel.db')
    
    # Ensure instance directory exists
    os.makedirs(instance_dir, exist_ok=True)
    
    # Create Flask app
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your-secret-key-here'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize database
    from web_dashboard import db
    db.init_app(app)
    
    with app.app_context():
        # Create database tables
        db.create_all()
        
        # Import User model
        from web_dashboard.models import User
        
        # Check if admin user already exists
        admin_user = User.query.filter_by(username='admin').first()
        
        if admin_user:
            print("✅ Admin user already exists!")
            print(f"Username: {admin_user.username}")
            print(f"Email: {admin_user.email}")
            return
        
        # Create admin user
        admin_user = User(
            username='admin',
            email='admin@threatintel.local'
        )
        # Use sha256 method instead of scrypt to avoid LibreSSL compatibility issues
        admin_user.password_hash = generate_password_hash('admin123', method='pbkdf2:sha256')
        
        # Add to database
        db.session.add(admin_user)
        db.session.commit()
        
        print("✅ Default admin user created successfully!")
        print("Username: admin")
        print("Password: admin123")
        print("Email: admin@threatintel.local")
        print("\n🔐 You can now log in to the dashboard!")

if __name__ == '__main__':
    create_default_user() 