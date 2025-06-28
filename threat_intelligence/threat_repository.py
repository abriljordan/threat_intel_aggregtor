"""
Threat Intelligence Repository

This module provides a repository for storing and correlating threat intelligence
data including threat actors, malware families, vulnerabilities, and observables.
"""

import json
import logging
from typing import Dict, List, Optional
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, Float, Boolean, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
import os

logger = logging.getLogger(__name__)

# SQLAlchemy setup
DATABASE_URL = os.getenv('THREAT_INTEL_DATABASE_URL', 'postgresql+psycopg2://postgres:metasploit@localhost:5432/threat_intelligence')
engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
Base = declarative_base()

# SQLAlchemy models
class ThreatActor(Base):
    __tablename__ = 'threat_actors'
    id = Column(Integer, primary_key=True, autoincrement=True)
    actor_id = Column(String, unique=True)
    name = Column(String, nullable=False)
    aliases = Column(Text)
    description = Column(Text)
    country = Column(String)
    motivation = Column(String)
    capabilities = Column(Text)
    first_seen = Column(String)
    last_seen = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class MalwareFamily(Base):
    __tablename__ = 'malware_families'
    id = Column(Integer, primary_key=True, autoincrement=True)
    malware_id = Column(String, unique=True)
    name = Column(String, nullable=False)
    aliases = Column(Text)
    description = Column(Text)
    family_type = Column(String)
    capabilities = Column(Text)
    iocs = Column(Text)
    behavior_patterns = Column(Text)
    first_seen = Column(String)
    last_seen = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String, unique=True)
    title = Column(String, nullable=False)
    description = Column(Text)
    severity = Column(String)
    cvss_score = Column(Float)
    affected_products = Column(Text)
    exploit_available = Column(Boolean, default=False)
    patch_available = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Observable(Base):
    __tablename__ = 'observables'
    id = Column(Integer, primary_key=True, autoincrement=True)
    observable_id = Column(String, unique=True, nullable=True)
    type = Column(String, nullable=False)
    value = Column(String, nullable=False)
    confidence = Column(Float, default=0.0)
    threat_score = Column(Integer, default=0)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    tags = Column(Text)
    meta = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Create tables if they don't exist
Base.metadata.create_all(bind=engine)

class ThreatIntelligenceRepository:
    def __init__(self, db_session=None):
        self.db = db_session or SessionLocal()

    def store_threat_actor(self, actor_data: Dict) -> bool:
        try:
            actor = ThreatActor(
                actor_id=actor_data.get('actor_id'),
                name=actor_data.get('name'),
                aliases=json.dumps(actor_data.get('aliases', [])),
                description=actor_data.get('description'),
                country=actor_data.get('country'),
                motivation=actor_data.get('motivation'),
                capabilities=json.dumps(actor_data.get('capabilities', [])),
                first_seen=actor_data.get('first_seen'),
                last_seen=actor_data.get('last_seen'),
            )
            self.db.merge(actor)
            self.db.commit()
            logger.info(f"Stored threat actor: {actor_data.get('name')}")
            return True
        except Exception as e:
            logger.error(f"Error storing threat actor: {e}")
            self.db.rollback()
            return False

    def store_malware_family(self, malware_data: Dict) -> bool:
        try:
            malware = MalwareFamily(
                malware_id=malware_data.get('malware_id'),
                name=malware_data.get('name'),
                aliases=json.dumps(malware_data.get('aliases', [])),
                description=malware_data.get('description'),
                family_type=malware_data.get('family_type'),
                capabilities=json.dumps(malware_data.get('capabilities', [])),
                iocs=json.dumps(malware_data.get('iocs', [])),
                behavior_patterns=json.dumps(malware_data.get('behavior_patterns', [])),
                first_seen=malware_data.get('first_seen'),
                last_seen=malware_data.get('last_seen'),
            )
            self.db.merge(malware)
            self.db.commit()
            logger.info(f"Stored malware family: {malware_data.get('name')}")
            return True
        except Exception as e:
            logger.error(f"Error storing malware family: {e}")
            self.db.rollback()
            return False

    def store_vulnerability(self, vuln_data: Dict) -> bool:
        try:
            vuln = Vulnerability(
                cve_id=vuln_data.get('cve_id'),
                title=vuln_data.get('title'),
                description=vuln_data.get('description'),
                severity=vuln_data.get('severity'),
                cvss_score=vuln_data.get('cvss_score'),
                affected_products=vuln_data.get('affected_products'),
                exploit_available=vuln_data.get('exploit_available', False),
                patch_available=vuln_data.get('patch_available', False),
            )
            self.db.merge(vuln)
            self.db.commit()
            logger.info(f"Stored vulnerability: {vuln_data.get('cve_id')}")
            return True
        except Exception as e:
            logger.error(f"Error storing vulnerability: {e}")
            self.db.rollback()
            return False

    def store_observable(self, observable_data: Dict) -> bool:
        try:
            observable = Observable(
                observable_id=observable_data.get('observable_id'),
                type=observable_data.get('type'),
                value=observable_data.get('value'),
                confidence=observable_data.get('confidence', 0.0),
                threat_score=observable_data.get('threat_score', 0),
                tags=json.dumps(observable_data.get('tags', [])),
                meta=json.dumps(observable_data.get('metadata', {})),
            )
            self.db.add(observable)
            self.db.commit()
            logger.info(f"Stored observable: {observable_data.get('value')}")
            return True
        except Exception as e:
            logger.error(f"Error storing observable: {e}")
            self.db.rollback()
            return False

    def clear_all_data(self):
        try:
            self.db.query(ThreatActor).delete()
            self.db.query(MalwareFamily).delete()
            self.db.query(Vulnerability).delete()
            self.db.query(Observable).delete()
            self.db.commit()
            logger.info("Cleared all threat intelligence data.")
        except Exception as e:
            logger.error(f"Error clearing all data: {e}")
            self.db.rollback()

    def close(self):
        self.db.close()

    def get_threat_statistics(self) -> Dict:
        """Get threat intelligence statistics from the database."""
        try:
            # Count threat actors
            threat_actors_count = self.db.query(func.count(ThreatActor.id)).scalar()
            
            # Count malware families
            malware_families_count = self.db.query(func.count(MalwareFamily.id)).scalar()
            
            # Count vulnerabilities
            vulnerabilities_count = self.db.query(func.count(Vulnerability.id)).scalar()
            
            # Count observables
            observables_count = self.db.query(func.count(Observable.id)).scalar()
            
            # Count high threat observables (threat_score >= 70)
            high_threat_observables_count = self.db.query(func.count(Observable.id)).filter(
                Observable.threat_score >= 70
            ).scalar()
            
            return {
                'threat_actors': threat_actors_count or 0,
                'malware_families': malware_families_count or 0,
                'vulnerabilities': vulnerabilities_count or 0,
                'observables': observables_count or 0,
                'high_threat_observables': high_threat_observables_count or 0
            }
            
        except Exception as e:
            logger.error(f"Error getting threat statistics: {e}")
            return {
                'threat_actors': 0,
                'malware_families': 0,
                'vulnerabilities': 0,
                'observables': 0,
                'high_threat_observables': 0
            }

    def search_threat_actors(self, query: str = '') -> List[Dict]:
        """Search threat actors by name or description."""
        try:
            if query:
                actors = self.db.query(ThreatActor).filter(
                    ThreatActor.name.ilike(f'%{query}%') | 
                    ThreatActor.description.ilike(f'%{query}%')
                ).limit(50).all()
            else:
                actors = self.db.query(ThreatActor).limit(50).all()
            
            return [
                {
                    'id': actor.id,
                    'actor_id': actor.actor_id,
                    'name': actor.name,
                    'aliases': json.loads(actor.aliases) if actor.aliases else [],
                    'description': actor.description,
                    'country': actor.country,
                    'motivation': actor.motivation,
                    'capabilities': json.loads(actor.capabilities) if actor.capabilities else [],
                    'first_seen': actor.first_seen,
                    'last_seen': actor.last_seen
                }
                for actor in actors
            ]
            
        except Exception as e:
            logger.error(f"Error searching threat actors: {e}")
            return []

    def search_malware_families(self, query: str = '') -> List[Dict]:
        """Search malware families by name or description."""
        try:
            if query:
                malware = self.db.query(MalwareFamily).filter(
                    MalwareFamily.name.ilike(f'%{query}%') | 
                    MalwareFamily.description.ilike(f'%{query}%')
                ).limit(50).all()
            else:
                malware = self.db.query(MalwareFamily).limit(50).all()
            
            return [
                {
                    'id': m.id,
                    'malware_id': m.malware_id,
                    'name': m.name,
                    'aliases': json.loads(m.aliases) if m.aliases else [],
                    'description': m.description,
                    'family_type': m.family_type,
                    'capabilities': json.loads(m.capabilities) if m.capabilities else [],
                    'iocs': json.loads(m.iocs) if m.iocs else [],
                    'behavior_patterns': json.loads(m.behavior_patterns) if m.behavior_patterns else [],
                    'first_seen': m.first_seen,
                    'last_seen': m.last_seen
                }
                for m in malware
            ]
            
        except Exception as e:
            logger.error(f"Error searching malware families: {e}")
            return []

    def search_observables(self, query: str = '') -> List[Dict]:
        """Search observables by value or type."""
        try:
            if query:
                observables = self.db.query(Observable).filter(
                    Observable.value.ilike(f'%{query}%') | 
                    Observable.type.ilike(f'%{query}%')
                ).limit(50).all()
            else:
                observables = self.db.query(Observable).limit(50).all()
            
            return [
                {
                    'id': obs.id,
                    'observable_id': obs.observable_id,
                    'type': obs.type,
                    'value': obs.value,
                    'confidence': obs.confidence,
                    'threat_score': obs.threat_score,
                    'tags': json.loads(obs.tags) if obs.tags else [],
                    'meta': json.loads(obs.meta) if obs.meta else {},
                    'first_seen': obs.first_seen.isoformat() if obs.first_seen else None,
                    'last_seen': obs.last_seen.isoformat() if obs.last_seen else None
                }
                for obs in observables
            ]
            
        except Exception as e:
            logger.error(f"Error searching observables: {e}")
            return []

# Flask-style per-request repository
from flask import g

def get_threat_repository():
    if 'repo' not in g:
        g.repo = ThreatIntelligenceRepository()
    return g.repo 