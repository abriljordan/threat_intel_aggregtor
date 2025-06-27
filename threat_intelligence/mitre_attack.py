"""
MITRE ATT&CK Framework Integration

This module provides integration with the MITRE ATT&CK framework for
mapping threat behaviors to known attack techniques and tactics.
"""

import requests
import json
import logging
from typing import Dict, List, Optional, Set
from datetime import datetime
import os
import sys

logger = logging.getLogger(__name__)

class MitreAttackIntegration:
    """MITRE ATT&CK Framework integration for threat intelligence."""
    
    def __init__(self, cache_dir: str = "cache/mitre"):
        """Initialize MITRE ATT&CK integration."""
        self.cache_dir = cache_dir
        self.techniques = {}
        self.tactics = {}
        self.relationships = {}
        self.threat_actors = {}
        self.malware = {}
        
        # Create cache directory
        os.makedirs(cache_dir, exist_ok=True)
        
        # MITRE ATT&CK API endpoints
        self.base_url = "https://attack.mitre.org/api/"
        self.enterprise_url = "https://attack.mitre.org/api/enterprise/"
        
        # Load sample data immediately for fallback
        self._load_sample_data()
        
        # Try to load or fetch ATT&CK data in background
        try:
            self._load_attack_data()
        except Exception as e:
            logger.warning(f"Could not load ATT&CK data: {e}. Using sample data.")
            # Sample data is already loaded above
    
    def _load_attack_data(self):
        """Load ATT&CK data from cache or fetch from API."""
        try:
            # Try to load from cache first
            if self._load_from_cache():
                logger.info("Loaded MITRE ATT&CK data from cache")
                return
            
            # Fetch from API if cache is empty or outdated
            logger.info("Fetching MITRE ATT&CK data from API...")
            self._fetch_attack_data()
            self._save_to_cache()
            
        except Exception as e:
            logger.error(f"Error loading ATT&CK data: {e}")
            # Load sample data as fallback
            self._load_sample_data()
    
    def _load_from_cache(self) -> bool:
        """Load ATT&CK data from cache files."""
        try:
            cache_files = [
                'techniques.json',
                'tactics.json', 
                'relationships.json',
                'threat_actors.json',
                'malware.json'
            ]
            
            for filename in cache_files:
                filepath = os.path.join(self.cache_dir, filename)
                if not os.path.exists(filepath):
                    return False
                
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    
                if filename == 'techniques.json':
                    self.techniques = data
                elif filename == 'tactics.json':
                    self.tactics = data
                elif filename == 'relationships.json':
                    self.relationships = data
                elif filename == 'threat_actors.json':
                    self.threat_actors = data
                elif filename == 'malware.json':
                    self.malware = data
            
            return True
            
        except Exception as e:
            logger.error(f"Error loading from cache: {e}")
            return False
    
    def _save_to_cache(self):
        """Save ATT&CK data to cache files."""
        try:
            cache_data = [
                (self.techniques, 'techniques.json'),
                (self.tactics, 'tactics.json'),
                (self.relationships, 'relationships.json'),
                (self.threat_actors, 'threat_actors.json'),
                (self.malware, 'malware.json')
            ]
            
            for data, filename in cache_data:
                filepath = os.path.join(self.cache_dir, filename)
                with open(filepath, 'w') as f:
                    json.dump(data, f, indent=2)
                    
        except Exception as e:
            logger.error(f"Error saving to cache: {e}")
    
    def _fetch_attack_data(self):
        """Fetch ATT&CK data from MITRE API."""
        try:
            # Set timeout for requests
            timeout = 10
            
            # Fetch techniques
            techniques_response = requests.get(f"{self.enterprise_url}techniques/", timeout=timeout)
            if techniques_response.status_code == 200:
                self.techniques = self._parse_techniques(techniques_response.json())
            
            # Fetch tactics
            tactics_response = requests.get(f"{self.enterprise_url}tactics/", timeout=timeout)
            if tactics_response.status_code == 200:
                self.tactics = self._parse_tactics(tactics_response.json())
            
            # Fetch threat actors
            actors_response = requests.get(f"{self.enterprise_url}groups/", timeout=timeout)
            if actors_response.status_code == 200:
                self.threat_actors = self._parse_threat_actors(actors_response.json())
            
            # Fetch malware
            malware_response = requests.get(f"{self.enterprise_url}malware/", timeout=timeout)
            if malware_response.status_code == 200:
                self.malware = self._parse_malware(malware_response.json())
                
        except requests.exceptions.Timeout:
            logger.warning("Timeout while fetching ATT&CK data. Using sample data.")
        except requests.exceptions.ConnectionError:
            logger.warning("Connection error while fetching ATT&CK data. Using sample data.")
        except Exception as e:
            logger.error(f"Error fetching ATT&CK data: {e}")
            # Sample data is already loaded in __init__
    
    def _parse_techniques(self, raw_data: List[Dict]) -> Dict:
        """Parse techniques data from API response."""
        techniques = {}
        for item in raw_data:
            if 'external_references' in item:
                for ref in item['external_references']:
                    if ref.get('source_name') == 'mitre-attack':
                        technique_id = ref.get('external_id')
                        if technique_id:
                            techniques[technique_id] = {
                                'id': technique_id,
                                'name': item.get('name', ''),
                                'description': item.get('description', ''),
                                'tactic': item.get('kill_chain_phases', [{}])[0].get('phase_name', ''),
                                'url': f"https://attack.mitre.org/techniques/{technique_id}",
                                'platforms': item.get('x_mitre_platforms', []),
                                'permissions_required': item.get('x_mitre_permissions_required', []),
                                'data_sources': item.get('x_mitre_data_sources', [])
                            }
        return techniques
    
    def _parse_tactics(self, raw_data: List[Dict]) -> Dict:
        """Parse tactics data from API response."""
        tactics = {}
        for item in raw_data:
            if 'external_references' in item:
                for ref in item['external_references']:
                    if ref.get('source_name') == 'mitre-attack':
                        tactic_id = ref.get('external_id')
                        if tactic_id:
                            tactics[tactic_id] = {
                                'id': tactic_id,
                                'name': item.get('name', ''),
                                'description': item.get('description', ''),
                                'url': f"https://attack.mitre.org/tactics/{tactic_id}"
                            }
        return tactics
    
    def _parse_threat_actors(self, raw_data: List[Dict]) -> Dict:
        """Parse threat actors data from API response."""
        actors = {}
        for item in raw_data:
            if 'external_references' in item:
                for ref in item['external_references']:
                    if ref.get('source_name') == 'mitre-attack':
                        actor_id = ref.get('external_id')
                        if actor_id:
                            actors[actor_id] = {
                                'id': actor_id,
                                'name': item.get('name', ''),
                                'description': item.get('description', ''),
                                'aliases': item.get('aliases', []),
                                'url': f"https://attack.mitre.org/groups/{actor_id}"
                            }
        return actors
    
    def _parse_malware(self, raw_data: List[Dict]) -> Dict:
        """Parse malware data from API response."""
        malware = {}
        for item in raw_data:
            if 'external_references' in item:
                for ref in item['external_references']:
                    if ref.get('source_name') == 'mitre-attack':
                        malware_id = ref.get('external_id')
                        if malware_id:
                            malware[malware_id] = {
                                'id': malware_id,
                                'name': item.get('name', ''),
                                'description': item.get('description', ''),
                                'aliases': item.get('aliases', []),
                                'url': f"https://attack.mitre.org/software/{malware_id}"
                            }
        return malware
    
    def _load_sample_data(self):
        """Load sample ATT&CK data for testing."""
        self.techniques = {
            'T1055': {
                'id': 'T1055',
                'name': 'Process Injection',
                'description': 'Adversaries may inject code into processes to evade process-based defenses.',
                'tactic': 'defense-evasion',
                'url': 'https://attack.mitre.org/techniques/T1055',
                'platforms': ['Windows', 'Linux', 'macOS'],
                'permissions_required': ['User', 'Administrator'],
                'data_sources': ['Process monitoring', 'API monitoring']
            },
            'T1071': {
                'id': 'T1071',
                'name': 'Application Layer Protocol',
                'description': 'Adversaries may communicate using application layer protocols.',
                'tactic': 'command-and-control',
                'url': 'https://attack.mitre.org/techniques/T1071',
                'platforms': ['Windows', 'Linux', 'macOS'],
                'permissions_required': ['User'],
                'data_sources': ['Network traffic analysis']
            }
        }
        
        self.tactics = {
            'TA0001': {
                'id': 'TA0001',
                'name': 'Initial Access',
                'description': 'The adversary is trying to get into your network.',
                'url': 'https://attack.mitre.org/tactics/TA0001'
            },
            'TA0002': {
                'id': 'TA0002', 
                'name': 'Execution',
                'description': 'The adversary is trying to run malicious code.',
                'url': 'https://attack.mitre.org/tactics/TA0002'
            }
        }
    
    def map_process_behavior(self, process_data: Dict) -> List[Dict]:
        """Map process behavior to ATT&CK techniques."""
        mapped_techniques = []
        
        # Analyze process characteristics
        process_name = process_data.get('name', '').lower()
        process_path = process_data.get('path', '').lower()
        connections = process_data.get('connections', [])
        
        # Check for process injection indicators
        if any(indicator in process_name for indicator in ['inject', 'dll', 'hook']):
            mapped_techniques.append({
                'technique': self.techniques.get('T1055'),
                'confidence': 'medium',
                'evidence': f'Process name suggests injection: {process_name}'
            })
        
        # Check for network communication
        if connections:
            mapped_techniques.append({
                'technique': self.techniques.get('T1071'),
                'confidence': 'high',
                'evidence': f'Process has {len(connections)} network connections'
            })
        
        return mapped_techniques
    
    def get_attack_chain(self, threat_actor: str) -> Dict:
        """Get attack chain for specific threat actor."""
        # This would typically fetch from MITRE API
        # For now, return sample data
        return {
            'threat_actor': threat_actor,
            'attack_chain': [
                {
                    'tactic': 'Initial Access',
                    'techniques': ['T1078', 'T1133', 'T1190'],
                    'description': 'Gain initial access to target environment'
                },
                {
                    'tactic': 'Execution',
                    'techniques': ['T1059', 'T1106', 'T1129'],
                    'description': 'Execute malicious code on target systems'
                },
                {
                    'tactic': 'Persistence',
                    'techniques': ['T1053', 'T1060', 'T1078'],
                    'description': 'Maintain access to target environment'
                }
            ]
        }
    
    def search_techniques(self, query: str) -> List[Dict]:
        """Search for ATT&CK techniques by name or description."""
        results = []
        query_lower = query.lower()
        
        for technique_id, technique in self.techniques.items():
            if (query_lower in technique['name'].lower() or 
                query_lower in technique['description'].lower()):
                results.append(technique)
        
        return results
    
    def get_technique_by_id(self, technique_id: str) -> Optional[Dict]:
        """Get technique information by ID."""
        return self.techniques.get(technique_id)
    
    def get_tactic_techniques(self, tactic_id: str) -> List[Dict]:
        """Get all techniques for a specific tactic."""
        results = []
        for technique in self.techniques.values():
            if technique.get('tactic') == tactic_id:
                results.append(technique)
        return results
    
    def get_threat_actor_techniques(self, actor_id: str) -> List[Dict]:
        """Get techniques associated with a threat actor."""
        # This would typically query MITRE API for actor-technique relationships
        # For now, return sample data
        return [
            self.techniques.get('T1055'),
            self.techniques.get('T1071')
        ]
    
    def calculate_threat_score(self, mapped_techniques: List[Dict]) -> int:
        """Calculate threat score based on mapped techniques."""
        if not mapped_techniques:
            return 0
        
        # Base score from number of techniques
        base_score = len(mapped_techniques) * 10
        
        # Adjust based on technique severity
        severity_multiplier = 1.0
        for technique in mapped_techniques:
            if technique.get('confidence') == 'high':
                severity_multiplier += 0.5
            elif technique.get('confidence') == 'medium':
                severity_multiplier += 0.25
        
        return min(int(base_score * severity_multiplier), 100)
    
    def get_attack_matrix(self) -> Dict:
        """Get the complete ATT&CK matrix structure."""
        matrix = {}
        for tactic_id, tactic in self.tactics.items():
            matrix[tactic_id] = {
                'tactic': tactic,
                'techniques': self.get_tactic_techniques(tactic_id)
            }
        return matrix

# Global instance - lazy loaded
_mitre_attack_instance = None

def get_mitre_attack():
    """Get the global MITRE ATT&CK instance (lazy loaded)."""
    global _mitre_attack_instance
    if _mitre_attack_instance is None:
        _mitre_attack_instance = MitreAttackIntegration()
    return _mitre_attack_instance 