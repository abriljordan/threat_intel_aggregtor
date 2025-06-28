#!/usr/bin/env python3
"""
Database Migration Script

This script migrates the existing User table to add the missing created_at column.
"""

import os
import sys
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def migrate_user_table():
    """Add created_at column to User table if it doesn't exist."""
    
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    print("🔧 Migrating User table to add created_at column...")
    
    try:
        # Import Flask app and database
        from web_dashboard import create_app, db
        
        app = create_app()
        
        with app.app_context():
            # Check if created_at column exists
            inspector = db.inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('user')]
            
            if 'created_at' in columns:
                print("✅ created_at column already exists in User table")
                return True
            
            print("📋 Adding created_at column to User table...")
            
            # Add the column
            db.engine.execute('ALTER TABLE user ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP')
            
            # Update existing users with current timestamp
            db.engine.execute('UPDATE user SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL')
            
            print("✅ Successfully added created_at column to User table")
            
            # Verify the column was added
            columns = [col['name'] for col in inspector.get_columns('user')]
            if 'created_at' in columns:
                print("✅ Column verification successful")
                return True
            else:
                print("❌ Column verification failed")
                return False
        
    except Exception as e:
        print(f"❌ Error migrating User table: {e}")
        return False

def verify_migration():
    """Verify that the migration was successful."""
    try:
        from web_dashboard import create_app, db
        from web_dashboard.models import User
        
        app = create_app()
        
        with app.app_context():
            # Try to query users with created_at
            users = User.query.all()
            print(f"✅ Successfully queried {len(users)} users with created_at column")
            
            for user in users:
                print(f"   - {user.username}: {user.created_at}")
            
            return True
            
    except Exception as e:
        print(f"❌ Migration verification failed: {e}")
        return False

def main():
    """Main migration function."""
    print("🚀 Starting User table migration...")
    
    # Run migration
    if migrate_user_table():
        print("\n🔍 Verifying migration...")
        if verify_migration():
            print("\n🎉 Migration completed successfully!")
            print("\nYou can now use the user management features:")
            print("  python manage_users.py list")
            print("  python manage_users.py create username email@example.com password")
        else:
            print("\n⚠️  Migration completed but verification failed")
    else:
        print("\n❌ Migration failed")

if __name__ == '__main__':
    main() 