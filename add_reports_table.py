#!/usr/bin/env python3
"""
Add Reports Table to Existing PostgreSQL Database

This script adds the reports table to your existing PostgreSQL database.
"""

import os
import sys
from dotenv import load_dotenv

def add_reports_table():
    """Add the reports table to the existing database."""
    
    # Load environment variables
    load_dotenv()
    
    print("🔧 Adding reports table to existing PostgreSQL database...")
    
    try:
        # Import Flask app and database
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        from web_dashboard import create_app, db
        from web_dashboard.models import Report
        
        app = create_app()
        
        with app.app_context():
            # Create the reports table
            Report.__table__.create(db.engine, checkfirst=True)
            print("✅ Reports table created successfully")
            
            # Check if table exists
            inspector = db.inspect(db.engine)
            if 'reports' in inspector.get_table_names():
                print("✅ Reports table verified in database")
            else:
                print("❌ Reports table not found")
                return False
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating reports table: {e}")
        return False

def migrate_existing_reports():
    """Migrate existing report files to the new reports table."""
    
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
    print("🚀 Adding Reports Table to Existing PostgreSQL Database")
    print("=" * 60)
    
    if add_reports_table():
        migrate_existing_reports()
        print("\n🎉 Reports table added successfully!")
        print("\nNext steps:")
        print("1. Restart your Flask application")
        print("2. Try searching for an IP address")
        print("3. Check that reports are saved to the reports table")
    else:
        print("\n❌ Failed to add reports table.") 