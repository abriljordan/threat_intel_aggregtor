#!/usr/bin/env python3
"""
PostgreSQL Database Setup Script

This script helps set up the PostgreSQL database for the threat intelligence system.
"""

import os
import sys
from dotenv import load_dotenv
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

def setup_postgresql_database():
    """Set up PostgreSQL database and tables."""
    
    # Load environment variables
    load_dotenv()
    
    # Get database connection details
    database_url = os.getenv('THREAT_INTEL_DATABASE_URL')
    if not database_url:
        print("❌ THREAT_INTEL_DATABASE_URL not found in .env file")
        return False
    
    try:
        # Parse connection string
        # Format: postgresql+psycopg2://username:password@host:port/database
        if 'postgresql+psycopg2://' in database_url:
            connection_string = database_url.replace('postgresql+psycopg2://', '')
        else:
            connection_string = database_url.replace('postgresql://', '')
        
        # Extract components
        auth_part, rest = connection_string.split('@', 1)
        username, password = auth_part.split(':', 1)
        host_port, database = rest.split('/', 1)
        host, port = host_port.split(':')
        
        print(f"🔧 Setting up PostgreSQL database...")
        print(f"   Host: {host}:{port}")
        print(f"   Database: {database}")
        print(f"   Username: {username}")
        
        # Connect to PostgreSQL server (without specifying database)
        conn = psycopg2.connect(
            host=host,
            port=port,
            user=username,
            password=password
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        
        # Check if database exists
        cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (database,))
        exists = cursor.fetchone()
        
        if not exists:
            print(f"📁 Creating database '{database}'...")
            cursor.execute(f'CREATE DATABASE "{database}"')
            print(f"✅ Database '{database}' created successfully")
        else:
            print(f"✅ Database '{database}' already exists")
        
        cursor.close()
        conn.close()
        
        # Now connect to the specific database and create tables
        print("📋 Creating tables...")
        
        # Import Flask app to create tables
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        from web_dashboard import create_app, db
        
        app = create_app()
        with app.app_context():
            db.create_all()
            print("✅ Tables created successfully")
        
        print("🎉 PostgreSQL database setup completed!")
        return True
        
    except Exception as e:
        print(f"❌ Error setting up PostgreSQL database: {e}")
        return False

def migrate_existing_reports():
    """Migrate existing report files to PostgreSQL database."""
    
    print("🔄 Migrating existing report files to database...")
    
    try:
        from web_dashboard import create_app, db
        from web_dashboard.models import Report
        import json
        import glob
        from datetime import datetime
        
        app = create_app()
        with app.app_context():
            # Get existing report files
            reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
            if not os.path.exists(reports_dir):
                print("📁 No reports directory found")
                return
            
            report_files = glob.glob(os.path.join(reports_dir, 'report_*.json'))
            print(f"📁 Found {len(report_files)} report files to migrate")
            
            migrated_count = 0
            for report_file in report_files:
                try:
                    with open(report_file, 'r') as f:
                        data = json.load(f)
                    
                    target = data.get('target', '').strip()
                    timestamp_str = data.get('timestamp')
                    results = data.get('results', {})
                    
                    if not target:
                        continue
                    
                    # Check if report already exists in database
                    existing = Report.query.filter_by(target=target).first()
                    if existing:
                        continue
                    
                    # Create new report
                    report = Report(target=target)
                    if timestamp_str:
                        try:
                            report.created_at = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        except:
                            pass
                    
                    report.set_results(results)
                    db.session.add(report)
                    migrated_count += 1
                    
                except Exception as e:
                    print(f"⚠️  Error migrating {report_file}: {e}")
                    continue
            
            db.session.commit()
            print(f"✅ Migrated {migrated_count} reports to database")
            
    except Exception as e:
        print(f"❌ Error during migration: {e}")

if __name__ == "__main__":
    print("🚀 PostgreSQL Database Setup for Threat Intelligence System")
    print("=" * 60)
    
    # Install psycopg2 if not available
    try:
        import psycopg2
    except ImportError:
        print("📦 Installing psycopg2-binary...")
        os.system("pip install psycopg2-binary==2.9.9")
        import psycopg2
    
    # Setup database
    if setup_postgresql_database():
        # Migrate existing data
        migrate_existing_reports()
        print("\n🎉 Setup completed successfully!")
        print("\nNext steps:")
        print("1. Restart your Flask application")
        print("2. Try searching for an IP address")
        print("3. Check that reports are saved to PostgreSQL")
    else:
        print("\n❌ Setup failed. Please check your PostgreSQL connection.") 