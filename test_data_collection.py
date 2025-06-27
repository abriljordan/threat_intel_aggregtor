#!/usr/bin/env python3
"""
Test script to verify data collection from the database.
"""

import sqlite3
import os
from datetime import datetime, timedelta

def test_database_queries():
    """Test the database queries used by the dashboard."""
    
    db_path = 'instance/threat_intel.db'
    if not os.path.exists(db_path):
        print("❌ Database file not found!")
        return
    
    print("🔍 Testing database queries...")
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Test 1: Threat categories
        print("\n1. Testing threat categories query...")
        cursor.execute('''
            SELECT category, COUNT(*) as count 
            FROM observables 
            WHERE category IS NOT NULL 
            GROUP BY category 
            ORDER BY count DESC
        ''')
        
        results = cursor.fetchall()
        print(f"Found {len(results)} categories:")
        for category, count in results:
            print(f"  - {category}: {count}")
        
        # Test 2: Threat timeline
        print("\n2. Testing threat timeline query...")
        cursor.execute('''
            SELECT DATE(first_seen) as date, COUNT(*) as count, AVG(threat_score) as avg_score
            FROM observables 
            WHERE first_seen >= DATE('now', '-30 days')
            GROUP BY DATE(first_seen)
            ORDER BY date
        ''')
        
        results = cursor.fetchall()
        print(f"Found {len(results)} timeline entries:")
        for date, count, avg_score in results:
            print(f"  - {date}: {count} threats, avg score: {avg_score:.1f}")
        
        # Test 3: Overall statistics
        print("\n3. Testing overall statistics...")
        cursor.execute('''
            SELECT 
                COUNT(*) as total_observables,
                AVG(threat_score) as avg_threat_score,
                COUNT(CASE WHEN threat_score >= 80 THEN 1 END) as high_threat_count,
                COUNT(CASE WHEN threat_score >= 50 THEN 1 END) as medium_threat_count
            FROM observables
        ''')
        
        result = cursor.fetchone()
        if result:
            total, avg_score, high_count, medium_count = result
            print(f"  - Total observables: {total}")
            print(f"  - Average threat score: {avg_score:.1f}")
            print(f"  - High threat observables (>=80): {high_count}")
            print(f"  - Medium+ threat observables (>=50): {medium_count}")
        
        # Test 4: Threat actors
        print("\n4. Testing threat actors query...")
        cursor.execute('''
            SELECT tags, COUNT(*) as count, AVG(threat_score) as avg_score
            FROM observables 
            WHERE tags IS NOT NULL 
            GROUP BY tags 
            ORDER BY avg_score DESC
        ''')
        
        results = cursor.fetchall()
        print(f"Found {len(results)} threat actor groups:")
        for tags, count, avg_score in results:
            print(f"  - {tags}: {count} observables, avg score: {avg_score:.1f}")
        
        conn.close()
        print("\n✅ Database queries completed successfully!")
        
    except Exception as e:
        print(f"❌ Error testing database queries: {e}")

def test_data_collection_functions():
    """Test the actual data collection functions from routes.py."""
    
    print("\n🔍 Testing data collection functions...")
    
    try:
        # Import the functions from routes
        import sys
        sys.path.append('.')
        
        # We need to mock the Flask app context
        from flask import Flask
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'test'
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/threat_intel.db'
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        
        with app.app_context():
            # Import and test the functions
            from web_dashboard.routes import (
                get_threat_categories_from_reports,
                get_threat_timeline_data,
                get_geographic_threat_data,
                get_threat_actors_data,
                get_malware_families_data
            )
            
            print("\n1. Testing threat categories function...")
            categories = get_threat_categories_from_reports()
            print(f"Categories: {categories}")
            
            print("\n2. Testing threat timeline function...")
            timeline = get_threat_timeline_data()
            print(f"Timeline entries: {len(timeline)}")
            
            print("\n3. Testing geographic threat function...")
            geo_data = get_geographic_threat_data()
            print(f"Geographic data: {geo_data}")
            
            print("\n4. Testing threat actors function...")
            actors = get_threat_actors_data()
            print(f"Threat actors: {actors}")
            
            print("\n5. Testing malware families function...")
            malware = get_malware_families_data()
            print(f"Malware families: {malware}")
            
        print("\n✅ Data collection functions completed successfully!")
        
    except Exception as e:
        print(f"❌ Error testing data collection functions: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    test_database_queries()
    test_data_collection_functions() 