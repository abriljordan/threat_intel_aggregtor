#!/usr/bin/env python3
"""
Script to populate the threat intelligence database with sample data.
This helps demonstrate the system's capabilities with realistic data.
"""

import sqlite3
import os
from datetime import datetime, timedelta
import random

def create_sample_data():
    """Create sample threat intelligence data."""
    
    # Connect to the database
    db_path = 'instance/threat_intel.db'
    os.makedirs('instance', exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create tables if they don't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_actors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            country TEXT,
            motivation TEXT,
            targets TEXT,
            first_seen TEXT,
            last_seen TEXT,
            threat_score INTEGER,
            tags TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS malware_families (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            family_type TEXT,
            first_seen TEXT,
            last_seen TEXT,
            threat_score INTEGER,
            tags TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS observables (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            description TEXT,
            threat_score INTEGER,
            category TEXT,
            first_seen TEXT,
            last_seen TEXT,
            tags TEXT,
            sources TEXT,
            details TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT,
            cvss_score REAL,
            affected_products TEXT,
            published_date TEXT,
            tags TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Sample threat actors
    threat_actors = [
        ('APT29 (Cozy Bear)', 'Russian state-sponsored threat group', 'Russia', 'Espionage', 'Government, Technology', 95),
        ('APT28 (Fancy Bear)', 'Russian military intelligence threat group', 'Russia', 'Espionage', 'Government, Defense', 90),
        ('Lazarus Group', 'North Korean state-sponsored group', 'North Korea', 'Financial Gain, Espionage', 'Financial, Technology', 88),
        ('Wizard Spider', 'Russian cybercriminal group', 'Russia', 'Financial Gain', 'Healthcare, Education', 85),
        ('Cobalt Group', 'Russian cybercriminal group', 'Russia', 'Financial Gain', 'Financial, Retail', 82),
        ('DarkHydrus', 'Iranian state-sponsored group', 'Iran', 'Espionage', 'Government, Technology', 80),
        ('APT41', 'Chinese state-sponsored group', 'China', 'Espionage', 'Technology, Healthcare', 85),
        ('APT40', 'Chinese state-sponsored group', 'China', 'Espionage', 'Government, Technology', 83)
    ]
    
    # Sample malware families
    malware_families = [
        ('Emotet', 'Banking trojan and malware delivery service', 'Trojan', 95),
        ('TrickBot', 'Modular banking trojan', 'Trojan', 90),
        ('Ryuk', 'Ransomware-as-a-Service', 'Ransomware', 88),
        ('Conti', 'Ransomware-as-a-Service', 'Ransomware', 85),
        ('QakBot', 'Modular banking trojan', 'Trojan', 82),
        ('Revil', 'Ransomware-as-a-Service', 'Ransomware', 80),
        ('LockBit', 'Ransomware-as-a-Service', 'Ransomware', 78),
        ('BlackCat', 'Ransomware-as-a-Service', 'Ransomware', 75)
    ]
    
    # Sample observables
    observables = [
        ('ip_address', '192.168.1.100', 'Emotet C2 server', 85, 'malware', ['emotet', 'c2']),
        ('domain', 'malware.example.com', 'TrickBot C2 domain', 90, 'malware', ['trickbot', 'c2']),
        ('hash', 'a1b2c3d4e5f6789012345678901234567890abcd', 'Emotet sample', 95, 'malware', ['emotet', 'trojan']),
        ('url', 'https://phish.example.com/login', 'Phishing site', 80, 'phishing', ['phishing', 'credential_theft']),
        ('ip_address', '10.0.0.1', 'APT29 infrastructure', 88, 'apt', ['apt29', 'espionage']),
        ('domain', 'c2.apt28.com', 'APT28 C2 domain', 85, 'apt', ['apt28', 'c2']),
        ('hash', 'b2c3d4e5f6789012345678901234567890abcde', 'Ryuk ransomware', 90, 'ransomware', ['ryuk', 'ransomware']),
        ('url', 'https://malware.example.org/payload', 'Malware download', 85, 'malware', ['malware', 'payload'])
    ]
    
    # Sample vulnerabilities
    vulnerabilities = [
        ('CVE-2024-1234', 'Microsoft Exchange Server RCE', 'Remote code execution vulnerability in Exchange Server', 'Critical', 9.8, 'Microsoft Exchange Server'),
        ('CVE-2024-5678', 'Apache Log4j RCE', 'Remote code execution in Apache Log4j', 'Critical', 10.0, 'Apache Log4j'),
        ('CVE-2024-9012', 'OpenSSL Buffer Overflow', 'Buffer overflow in OpenSSL library', 'High', 8.5, 'OpenSSL'),
        ('CVE-2024-3456', 'WordPress Plugin XSS', 'Cross-site scripting in WordPress plugin', 'Medium', 6.5, 'WordPress'),
        ('CVE-2024-7890', 'Linux Kernel Privilege Escalation', 'Privilege escalation in Linux kernel', 'High', 8.0, 'Linux Kernel')
    ]
    
    # Insert sample data
    now = datetime.now()
    
    # Insert threat actors
    for name, desc, country, motivation, targets, score in threat_actors:
        first_seen = now - timedelta(days=random.randint(365, 1095))
        last_seen = now - timedelta(days=random.randint(1, 30))
        
        cursor.execute('''
            INSERT INTO threat_actors (name, description, country, motivation, targets, first_seen, last_seen, threat_score, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (name, desc, country, motivation, targets, first_seen.isoformat(), last_seen.isoformat(), score, 'apt,state_sponsored'))
    
    # Insert malware families
    for name, desc, family_type, score in malware_families:
        first_seen = now - timedelta(days=random.randint(180, 730))
        last_seen = now - timedelta(days=random.randint(1, 60))
        
        cursor.execute('''
            INSERT INTO malware_families (name, description, family_type, first_seen, last_seen, threat_score, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (name, desc, family_type, first_seen.isoformat(), last_seen.isoformat(), score, 'malware,active'))
    
    # Insert observables
    for obs_type, value, desc, score, category, tags in observables:
        first_seen = now - timedelta(days=random.randint(30, 180))
        last_seen = now - timedelta(days=random.randint(1, 7))
        
        cursor.execute('''
            INSERT INTO observables (type, value, description, threat_score, category, first_seen, last_seen, tags, sources)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (obs_type, value, desc, score, category, first_seen.isoformat(), last_seen.isoformat(), ','.join(tags), 'Sample Source'))
    
    # Insert vulnerabilities
    for cve_id, title, desc, severity, cvss_score, affected in vulnerabilities:
        published_date = now - timedelta(days=random.randint(1, 90))
        
        cursor.execute('''
            INSERT INTO vulnerabilities (cve_id, title, description, severity, cvss_score, affected_products, published_date, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (cve_id, title, desc, severity, cvss_score, affected, published_date.isoformat(), 'vulnerability,active'))
    
    # Commit and close
    conn.commit()
    conn.close()
    
    print("✅ Sample data has been populated successfully!")
    print(f"📊 Database location: {db_path}")
    print("📈 Added sample data for:")
    print("   - 8 threat actors")
    print("   - 8 malware families") 
    print("   - 8 observables")
    print("   - 5 vulnerabilities")

if __name__ == '__main__':
    create_sample_data() 