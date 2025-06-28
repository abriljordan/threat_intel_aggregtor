#!/usr/bin/env python3
"""
User Management Script

This script provides administrative functions for managing users
in the threat intelligence system.
"""

import os
import sys
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from datetime import datetime

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def create_app():
    """Create Flask app for user management."""
    app = Flask(__name__)
    
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    # Configure database - default to PostgreSQL like the migration script
    database_url = os.getenv('DATABASE_URL', 'postgresql://postgres:metasploit@localhost:5432/threat_intelligence')
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    print(f"Using database: {database_url.split('@')[1] if '@' in database_url else database_url}")
    
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-key')
    
    # Initialize database
    from web_dashboard import db
    db.init_app(app)
    
    return app

def list_users():
    """List all users in the system."""
    app = create_app()
    
    with app.app_context():
        from web_dashboard.models import User
        
        try:
            users = User.query.all()
            
            if not users:
                print("No users found in the system.")
                return
            
            print(f"\n{'='*60}")
            print("USER LIST")
            print(f"{'='*60}")
            print(f"{'ID':<5} {'Username':<20} {'Email':<30} {'Created':<20}")
            print(f"{'-'*5} {'-'*20} {'-'*30} {'-'*20}")
            
            for user in users:
                # Handle case where created_at might not exist
                try:
                    created = user.created_at.strftime('%Y-%m-%d %H:%M') if user.created_at else 'Unknown'
                except AttributeError:
                    created = 'Unknown'
                print(f"{user.id:<5} {user.username:<20} {user.email:<30} {created:<20}")
            
            print(f"{'='*60}")
            print(f"Total users: {len(users)}")
            
        except Exception as e:
            print(f"❌ Error listing users: {e}")
            print("💡 Try running: python migrate_user_table.py")
            return False

def create_user(username, email, password, is_admin=False):
    """Create a new user."""
    app = create_app()
    
    with app.app_context():
        from web_dashboard.models import User
        
        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f"❌ User '{username}' already exists!")
            return False
        
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            print(f"❌ Email '{email}' already registered!")
            return False
        
        try:
            # Create new user
            user = User(username=username, email=email)
            user.set_password(password)
            
            # Add admin flag if needed (you can extend the User model for this)
            if is_admin:
                print(f"⚠️  Note: Admin privileges not implemented in current User model")
            
            # Save to database
            from web_dashboard import db
            db.session.add(user)
            db.session.commit()
            
            print(f"✅ User '{username}' created successfully!")
            print(f"   Username: {username}")
            print(f"   Email: {email}")
            print(f"   Created: {user.created_at.strftime('%Y-%m-%d %H:%M')}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error creating user: {e}")
            db.session.rollback()
            return False

def delete_user(username):
    """Delete a user by username."""
    app = create_app()
    
    with app.app_context():
        from web_dashboard.models import User
        
        user = User.query.filter_by(username=username).first()
        if not user:
            print(f"❌ User '{username}' not found!")
            return False
        
        try:
            # Prevent deletion of admin user
            if username == 'admin':
                print(f"❌ Cannot delete the admin user!")
                return False
            
            from web_dashboard import db
            db.session.delete(user)
            db.session.commit()
            
            print(f"✅ User '{username}' deleted successfully!")
            return True
            
        except Exception as e:
            print(f"❌ Error deleting user: {e}")
            db.session.rollback()
            return False

def reset_user_password(username, new_password):
    """Reset a user's password."""
    app = create_app()
    
    with app.app_context():
        from web_dashboard.models import User
        
        user = User.query.filter_by(username=username).first()
        if not user:
            print(f"❌ User '{username}' not found!")
            return False
        
        try:
            user.set_password(new_password)
            
            from web_dashboard import db
            db.session.commit()
            
            print(f"✅ Password for user '{username}' reset successfully!")
            return True
            
        except Exception as e:
            print(f"❌ Error resetting password: {e}")
            db.session.rollback()
            return False

def show_user_details(username):
    """Show detailed information about a user."""
    app = create_app()
    
    with app.app_context():
        from web_dashboard.models import User
        
        user = User.query.filter_by(username=username).first()
        if not user:
            print(f"❌ User '{username}' not found!")
            return False
        
        print(f"\n{'='*50}")
        print(f"USER DETAILS: {username}")
        print(f"{'='*50}")
        print(f"ID: {user.id}")
        print(f"Username: {user.username}")
        print(f"Email: {user.email}")
        
        # Handle case where created_at might not exist
        try:
            created = user.created_at.strftime('%Y-%m-%d %H:%M:%S') if user.created_at else 'Unknown'
        except AttributeError:
            created = 'Unknown (column not migrated)'
        
        print(f"Created: {created}")
        print(f"Password Hash: {user.password_hash[:20]}...")
        print(f"{'='*50}")
        
        return True

def main():
    """Main function to handle command line arguments."""
    if len(sys.argv) < 2:
        print("""
🔧 User Management Script

Usage:
  python manage_users.py <command> [options]

Commands:
  list                    - List all users
  create <username> <email> <password>  - Create a new user
  delete <username>       - Delete a user
  reset-password <username> <new_password>  - Reset user password
  show <username>         - Show user details

Examples:
  python manage_users.py list
  python manage_users.py create john john@example.com MyPassword123!
  python manage_users.py delete john
  python manage_users.py reset-password john NewPassword123!
  python manage_users.py show admin
        """)
        return
    
    command = sys.argv[1].lower()
    
    if command == 'list':
        list_users()
    
    elif command == 'create':
        if len(sys.argv) < 5:
            print("❌ Usage: python manage_users.py create <username> <email> <password>")
            return
        username = sys.argv[2]
        email = sys.argv[3]
        password = sys.argv[4]
        create_user(username, email, password)
    
    elif command == 'delete':
        if len(sys.argv) < 3:
            print("❌ Usage: python manage_users.py delete <username>")
            return
        username = sys.argv[2]
        delete_user(username)
    
    elif command == 'reset-password':
        if len(sys.argv) < 4:
            print("❌ Usage: python manage_users.py reset-password <username> <new_password>")
            return
        username = sys.argv[2]
        new_password = sys.argv[3]
        reset_user_password(username, new_password)
    
    elif command == 'show':
        if len(sys.argv) < 3:
            print("❌ Usage: python manage_users.py show <username>")
            return
        username = sys.argv[2]
        show_user_details(username)
    
    else:
        print(f"❌ Unknown command: {command}")
        print("Run 'python manage_users.py' for usage information.")

if __name__ == '__main__':
    main() 