"""
Threat Intelligence Repository

This module provides a repository for storing and correlating threat intelligence
data including threat actors, malware families, vulnerabilities, and observables.
"""

import json
import sqlite3
import logging
from typing import Dict, List, Optional, Set
from datetime import datetime
import os
from collections import defaultdict

logger = logging.getLogger(__name__)

class ThreatIntelligenceRepository:
    """Repository for storing and correlating threat intelligence data."""
    
    def __init__(self, db_path: str = "instance/threat_intelligence.db"):
        """Initialize the threat intelligence repository."""
        self.db_path = db_path
        self.conn = None
        try:
            self._init_database()
        except Exception as e:
            logger.error(f"Error initializing threat intelligence repository: {e}")
            # Create a dummy connection to prevent errors
            self.conn = None
    
    def _init_database(self):
        """Initialize the database with required tables."""
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            
            # Create tables
            self._create_tables()
            logger.info("Threat intelligence repository initialized")
            
        except Exception as e:
            logger.error(f"Error initializing threat intelligence repository: {e}")
    
    def _create_tables(self):
        """Create database tables for threat intelligence data."""
        cursor = self.conn.cursor()
        
        # Threat Actors table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_actors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id TEXT UNIQUE,
                name TEXT NOT NULL,
                aliases TEXT,
                description TEXT,
                country TEXT,
                motivation TEXT,
                capabilities TEXT,
                first_seen TEXT,
                last_seen TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Malware Families table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS malware_families (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                malware_id TEXT UNIQUE,
                name TEXT NOT NULL,
                aliases TEXT,
                description TEXT,
                family_type TEXT,
                capabilities TEXT,
                iocs TEXT,
                behavior_patterns TEXT,
                first_seen TEXT,
                last_seen TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT UNIQUE,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                affected_products TEXT,
                exploit_available BOOLEAN DEFAULT FALSE,
                patch_available BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Attack Techniques table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_techniques (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                technique_id TEXT UNIQUE,
                name TEXT NOT NULL,
                description TEXT,
                tactic TEXT,
                mitre_url TEXT,
                platforms TEXT,
                permissions_required TEXT,
                data_sources TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Observables table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS observables (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                observable_id TEXT UNIQUE,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                confidence REAL DEFAULT 0.0,
                threat_score INTEGER DEFAULT 0,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tags TEXT,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Relationships table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS relationships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_type TEXT NOT NULL,
                source_id TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                relationship_type TEXT NOT NULL,
                confidence REAL DEFAULT 0.0,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(source_type, source_id, target_type, target_id, relationship_type)
            )
        ''')
        
        # Threat Reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT UNIQUE,
                title TEXT NOT NULL,
                description TEXT,
                content TEXT,
                source TEXT,
                url TEXT,
                published_date TEXT,
                threat_actors TEXT,
                malware_families TEXT,
                attack_techniques TEXT,
                observables TEXT,
                tags TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.conn.commit()
    
    def store_threat_actor(self, actor_data: Dict) -> bool:
        """Store threat actor information."""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO threat_actors 
                (actor_id, name, aliases, description, country, motivation, capabilities, first_seen, last_seen, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                actor_data.get('actor_id'),
                actor_data.get('name'),
                json.dumps(actor_data.get('aliases', [])),
                actor_data.get('description'),
                actor_data.get('country'),
                actor_data.get('motivation'),
                json.dumps(actor_data.get('capabilities', [])),
                actor_data.get('first_seen'),
                actor_data.get('last_seen'),
                datetime.now().isoformat()
            ))
            
            self.conn.commit()
            logger.info(f"Stored threat actor: {actor_data.get('name')}")
            return True
            
        except Exception as e:
            logger.error(f"Error storing threat actor: {e}")
            return False
    
    def store_malware_family(self, malware_data: Dict) -> bool:
        """Store malware family information."""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO malware_families 
                (malware_id, name, aliases, description, family_type, capabilities, iocs, behavior_patterns, first_seen, last_seen, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                malware_data.get('malware_id'),
                malware_data.get('name'),
                json.dumps(malware_data.get('aliases', [])),
                malware_data.get('description'),
                malware_data.get('family_type'),
                json.dumps(malware_data.get('capabilities', [])),
                json.dumps(malware_data.get('iocs', [])),
                json.dumps(malware_data.get('behavior_patterns', [])),
                malware_data.get('first_seen'),
                malware_data.get('last_seen'),
                datetime.now().isoformat()
            ))
            
            self.conn.commit()
            logger.info(f"Stored malware family: {malware_data.get('name')}")
            return True
            
        except Exception as e:
            logger.error(f"Error storing malware family: {e}")
            return False
    
    def store_vulnerability(self, vuln_data: Dict) -> bool:
        """Store vulnerability information."""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO vulnerabilities 
                (cve_id, title, description, severity, cvss_score, affected_products, exploit_available, patch_available, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                vuln_data.get('cve_id'),
                vuln_data.get('title'),
                vuln_data.get('description'),
                vuln_data.get('severity'),
                vuln_data.get('cvss_score'),
                json.dumps(vuln_data.get('affected_products', [])),
                vuln_data.get('exploit_available', False),
                vuln_data.get('patch_available', False),
                datetime.now().isoformat()
            ))
            
            self.conn.commit()
            logger.info(f"Stored vulnerability: {vuln_data.get('cve_id')}")
            return True
            
        except Exception as e:
            logger.error(f"Error storing vulnerability: {e}")
            return False
    
    def store_observable(self, observable_data: Dict) -> bool:
        """Store observable (IOC) information."""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO observables 
                (observable_id, type, value, confidence, threat_score, tags, metadata, last_seen, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                observable_data.get('observable_id'),
                observable_data.get('type'),
                observable_data.get('value'),
                observable_data.get('confidence', 0.0),
                observable_data.get('threat_score', 0),
                json.dumps(observable_data.get('tags', [])),
                json.dumps(observable_data.get('metadata', {})),
                datetime.now().isoformat(),
                datetime.now().isoformat()
            ))
            
            self.conn.commit()
            logger.info(f"Stored observable: {observable_data.get('type')} - {observable_data.get('value')}")
            return True
            
        except Exception as e:
            logger.error(f"Error storing observable: {e}")
            return False
    
    def correlate_observables(self, ioc_data: Dict) -> Dict:
        """Correlate IOCs with known threats."""
        correlation_result = {
            'matches': [],
            'threat_actors': [],
            'malware_families': [],
            'vulnerabilities': [],
            'confidence': 0.0,
            'threat_score': 0
        }
        
        try:
            cursor = self.conn.cursor()
            
            # Search for matching observables
            cursor.execute('''
                SELECT * FROM observables 
                WHERE type = ? AND value = ?
            ''', (ioc_data.get('type'), ioc_data.get('value')))
            
            matches = cursor.fetchall()
            if matches:
                for match in matches:
                    correlation_result['matches'].append(dict(match))
                    
                    # Get related threat actors
                    cursor.execute('''
                        SELECT ta.* FROM threat_actors ta
                        JOIN relationships r ON ta.actor_id = r.target_id
                        WHERE r.source_type = 'observable' AND r.source_id = ?
                    ''', (match['observable_id'],))
                    
                    for actor in cursor.fetchall():
                        correlation_result['threat_actors'].append(dict(actor))
                    
                    # Get related malware families
                    cursor.execute('''
                        SELECT mf.* FROM malware_families mf
                        JOIN relationships r ON mf.malware_id = r.target_id
                        WHERE r.source_type = 'observable' AND r.source_id = ?
                    ''', (match['observable_id'],))
                    
                    for malware in cursor.fetchall():
                        correlation_result['malware_families'].append(dict(malware))
                
                # Calculate overall confidence and threat score
                if correlation_result['matches']:
                    correlation_result['confidence'] = max(match['confidence'] for match in correlation_result['matches'])
                    correlation_result['threat_score'] = max(match['threat_score'] for match in correlation_result['matches'])
            
        except Exception as e:
            logger.error(f"Error correlating observables: {e}")
        
        return correlation_result
    
    def search_threat_actors(self, query: str) -> List[Dict]:
        """Search for threat actors by name or description."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT * FROM threat_actors 
                WHERE name LIKE ? OR description LIKE ? OR aliases LIKE ?
            ''', (f'%{query}%', f'%{query}%', f'%{query}%'))
            
            return [dict(row) for row in cursor.fetchall()]
            
        except Exception as e:
            logger.error(f"Error searching threat actors: {e}")
            return []
    
    def search_malware_families(self, query: str) -> List[Dict]:
        """Search for malware families by name or description."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT * FROM malware_families 
                WHERE name LIKE ? OR description LIKE ? OR aliases LIKE ?
            ''', (f'%{query}%', f'%{query}%', f'%{query}%'))
            
            return [dict(row) for row in cursor.fetchall()]
            
        except Exception as e:
            logger.error(f"Error searching malware families: {e}")
            return []
    
    def get_threat_actor_details(self, actor_id: str) -> Optional[Dict]:
        """Get detailed information about a threat actor."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT * FROM threat_actors WHERE actor_id = ?', (actor_id,))
            
            row = cursor.fetchone()
            if row:
                return dict(row)
            
        except Exception as e:
            logger.error(f"Error getting threat actor details: {e}")
        
        return None
    
    def get_malware_family_details(self, malware_id: str) -> Optional[Dict]:
        """Get detailed information about a malware family."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT * FROM malware_families WHERE malware_id = ?', (malware_id,))
            
            row = cursor.fetchone()
            if row:
                return dict(row)
            
        except Exception as e:
            logger.error(f"Error getting malware family details: {e}")
        
        return None
    
    def get_recent_observables(self, limit: int = 100) -> List[Dict]:
        """Get recent observables."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT * FROM observables 
                ORDER BY last_seen DESC 
                LIMIT ?
            ''', (limit,))
            
            return [dict(row) for row in cursor.fetchall()]
            
        except Exception as e:
            logger.error(f"Error getting recent observables: {e}")
            return []
    
    def get_threat_statistics(self) -> Dict:
        """Get threat intelligence statistics."""
        try:
            cursor = self.conn.cursor()
            
            stats = {}
            
            # Count threat actors
            cursor.execute('SELECT COUNT(*) FROM threat_actors')
            stats['threat_actors'] = cursor.fetchone()[0]
            
            # Count malware families
            cursor.execute('SELECT COUNT(*) FROM malware_families')
            stats['malware_families'] = cursor.fetchone()[0]
            
            # Count vulnerabilities
            cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
            stats['vulnerabilities'] = cursor.fetchone()[0]
            
            # Count observables
            cursor.execute('SELECT COUNT(*) FROM observables')
            stats['observables'] = cursor.fetchone()[0]
            
            # Count high-threat observables
            cursor.execute('SELECT COUNT(*) FROM observables WHERE threat_score >= 70')
            stats['high_threat_observables'] = cursor.fetchone()[0]
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting threat statistics: {e}")
            return {}
    
    def create_relationship(self, source_type: str, source_id: str, 
                          target_type: str, target_id: str, 
                          relationship_type: str, confidence: float = 0.0) -> bool:
        """Create a relationship between threat intelligence entities."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO relationships 
                (source_type, source_id, target_type, target_id, relationship_type, confidence)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (source_type, source_id, target_type, target_id, relationship_type, confidence))
            
            self.conn.commit()
            return True
            
        except Exception as e:
            logger.error(f"Error creating relationship: {e}")
            return False
    
    def get_relationships(self, entity_type: str, entity_id: str) -> List[Dict]:
        """Get relationships for a specific entity."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT * FROM relationships 
                WHERE (source_type = ? AND source_id = ?) OR (target_type = ? AND target_id = ?)
            ''', (entity_type, entity_id, entity_type, entity_id))
            
            return [dict(row) for row in cursor.fetchall()]
            
        except Exception as e:
            logger.error(f"Error getting relationships: {e}")
            return []
    
    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()

# Global instance - lazy loaded
_threat_repository_instance = None

def get_threat_repository():
    """Get the global threat repository instance (lazy loaded)."""
    global _threat_repository_instance
    if _threat_repository_instance is None:
        _threat_repository_instance = ThreatIntelligenceRepository()
    return _threat_repository_instance 