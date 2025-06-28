"""
MITRE ATT&CK Framework Integration

This module provides integration with the MITRE ATT&CK framework using
the official mitreattack-python library for comprehensive threat intelligence.
"""

import json
import logging
from typing import Dict, List, Optional, Set
from datetime import datetime
import os
import sys
from mitreattack.stix20.MitreAttackData import MitreAttackData

logger = logging.getLogger(__name__)

try:
    from mitreattack.stix20 import MitreAttackData
    MITRE_AVAILABLE = True
except ImportError:
    MITRE_AVAILABLE = False
    logger.warning("mitreattack-python library not available. Install with: pip install mitreattack-python")

class MitreAttackIntegration:
    """MITRE ATT&CK integration with persistent caching."""
    
    def __init__(self, cache_dir: str = "cache/mitre"):
        """Initialize MITRE ATT&CK integration with caching."""
        self.cache_dir = cache_dir
        self.cache_file = os.path.join(cache_dir, "processed_data.json")
        self.mitre_data = None
        self.techniques = {}
        self.tactics = {}
        self.threat_actors = {}
        self.malware = {}
        self.relationships = {}
        self._loaded = False
        
        # Create cache directory if it doesn't exist
        os.makedirs(cache_dir, exist_ok=True)
        
        # Try to load from cache first, then from source if needed
        if not self._load_from_cache():
            self._load_attack_data()
    
    def _load_from_cache(self) -> bool:
        """Load processed data from cache file."""
        try:
            if not os.path.exists(self.cache_file):
                print("      📁 No cache found, will load from source...")
                return False
            
            print("      📁 Loading MITRE ATT&CK data from cache...")
            with open(self.cache_file, 'r') as f:
                cached_data = json.load(f)
            
            self.techniques = cached_data.get('techniques', {})
            self.tactics = cached_data.get('tactics', {})
            self.threat_actors = cached_data.get('threat_actors', {})
            self.malware = cached_data.get('malware', {})
            
            print(f"      ✅ Loaded from cache: {len(self.techniques)} techniques, {len(self.tactics)} tactics, {len(self.threat_actors)} threat actors, {len(self.malware)} malware")
            return True
            
        except Exception as e:
            print(f"      ⚠️  Cache loading failed: {e}")
            return False
    
    def _save_to_cache(self):
        """Save processed data to cache file."""
        try:
            cache_data = {
                'techniques': self.techniques,
                'tactics': self.tactics,
                'threat_actors': self.threat_actors,
                'malware': self.malware,
                'cache_timestamp': '2024-01-01T00:00:00Z'  # You could add actual timestamp
            }
            
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            
            print(f"      💾 Saved to cache: {len(self.techniques)} techniques, {len(self.tactics)} tactics, {len(self.threat_actors)} threat actors, {len(self.malware)} malware")
            
        except Exception as e:
            print(f"      ⚠️  Cache saving failed: {e}")
    
    def _load_attack_data(self):
        """Load MITRE ATT&CK data from source and cache it."""
        try:
            print("      📁 Reading enterprise-attack.json (43MB)...")
            
            # Load from the cached JSON file
            json_file = os.path.join(self.cache_dir, "enterprise-attack.json")
            if not os.path.exists(json_file):
                print("      ❌ enterprise-attack.json not found in cache directory")
                return
            
            self.mitre_data = MitreAttackData(json_file)
            print("      ✅ MITRE ATT&CK data loaded successfully")
            
            # Load all components
            self._load_tactics()
            self._load_techniques()
            self._load_threat_actors()
            self._load_malware()
            
            # Save to cache for future use
            self._save_to_cache()
            
        except Exception as e:
            print(f"      ❌ Error loading MITRE ATT&CK data: {e}")
            logger.error(f"Error loading MITRE ATT&CK data: {e}")
    
    def _load_techniques(self):
        """Load all techniques from MITRE ATT&CK."""
        try:
            if not self.mitre_data:
                return
            
            techniques = self.mitre_data.get_techniques(remove_revoked_deprecated=True)
            total_techniques = len(techniques)
            
            print(f"      🔧 Loading all techniques...")
            print(f"      📋 Processing {total_techniques} techniques...")
            
            for i, technique in enumerate(techniques):
                # Show progress every 50 techniques
                if i % 50 == 0:
                    print(f"      Processing technique {i+1}/{total_techniques}...")
                
                attack_id = self.mitre_data.get_attack_id(technique.id)
                if not attack_id:
                    continue
                
                # Get tactic information
                tactic_shortname = None
                if hasattr(technique, 'kill_chain_phases') and technique.kill_chain_phases:
                    for phase in technique.kill_chain_phases:
                        if phase.kill_chain_name == 'mitre-attack':
                            tactic_shortname = phase.phase_name
                            break
                
                self.techniques[attack_id] = {
                    'id': attack_id,
                    'name': technique.name,
                    'description': technique.description,
                    'tactic': tactic_shortname,
                    'sub_techniques': [],
                    'url': f"https://attack.mitre.org/techniques/{attack_id}",
                    'stix_id': technique.id,
                    'created': technique.created.isoformat() if technique.created else None,
                    'modified': technique.modified.isoformat() if technique.modified else None,
                    'platforms': getattr(technique, 'x_mitre_platforms', []),
                    'permissions_required': getattr(technique, 'x_mitre_permissions_required', []),
                    'data_sources': getattr(technique, 'x_mitre_data_sources', []),
                    'defense_bypassed': getattr(technique, 'x_mitre_defense_bypassed', []),
                    'detection': getattr(technique, 'x_mitre_detection', '')
                }
            
            print(f"      ✅ Loaded {len(self.techniques)} techniques")
            logger.info(f"Loaded {len(self.techniques)} techniques")
            
            # Verify we have a reasonable number of techniques
            if len(self.techniques) < 100:
                print(f"      ⚠️  Warning: Only loaded {len(self.techniques)} techniques, expected ~679")
                logger.warning(f"Only loaded {len(self.techniques)} techniques, expected ~679")
            
        except Exception as e:
            print(f"      ❌ Error loading techniques: {e}")
            logger.error(f"Error loading techniques: {e}")
    
    def _load_tactics(self):
        """Load all tactics from MITRE ATT&CK."""
        try:
            if not self.mitre_data:
                return
            
            tactics = self.mitre_data.get_tactics(remove_revoked_deprecated=True)
            total_tactics = len(tactics)
            
            print(f"      🎯 Loading all tactics...")
            
            for tactic in tactics:
                attack_id = self.mitre_data.get_attack_id(tactic.id)
                if not attack_id:
                    continue
                
                self.tactics[attack_id] = {
                    'id': attack_id,
                    'name': tactic.name,
                    'description': tactic.description,
                    'shortname': tactic.x_mitre_shortname if hasattr(tactic, 'x_mitre_shortname') else attack_id,
                    'url': f"https://attack.mitre.org/tactics/{attack_id}",
                    'stix_id': tactic.id,
                    'created': tactic.created.isoformat() if tactic.created else None,
                    'modified': tactic.modified.isoformat() if tactic.modified else None
                }
            
            print(f"      ✅ Loaded {len(self.tactics)} tactics")
            logger.info(f"Loaded {len(self.tactics)} tactics")
            
        except Exception as e:
            logger.error(f"Error loading tactics: {e}")
    
    def _load_threat_actors(self):
        """Load all threat actors from MITRE ATT&CK."""
        try:
            if not self.mitre_data:
                return
            
            groups = self.mitre_data.get_groups(remove_revoked_deprecated=True)
            total_groups = len(groups)
            
            print(f"      👥 Loading all threat actors...")
            print(f"      📋 Processing {total_groups} threat actors...")
            
            for i, group in enumerate(groups):
                # Show progress every 20 groups
                if i % 20 == 0:
                    print(f"      Processing threat actor {i+1}/{total_groups}...")
                
                attack_id = self.mitre_data.get_attack_id(group.id)
                if not attack_id:
                    continue
                
                # Get techniques used by this group
                group_techniques = self.mitre_data.get_techniques_used_by_group(group.id)
                technique_ids = []
                for tech_rel in group_techniques:
                    tech_id = self.mitre_data.get_attack_id(tech_rel['object'].id)
                    if tech_id:
                        technique_ids.append(tech_id)
                
                # Get software used by this group
                group_software = self.mitre_data.get_software_used_by_group(group.id)
                software_ids = []
                for sw_rel in group_software:
                    sw_id = self.mitre_data.get_attack_id(sw_rel['object'].id)
                    if sw_id:
                        software_ids.append(sw_id)
                
                self.threat_actors[attack_id] = {
                    'id': attack_id,
                    'name': group.name,
                    'description': group.description,
                    'aliases': group.aliases if hasattr(group, 'aliases') else [],
                    'techniques': technique_ids,
                    'software': software_ids,
                    'url': f"https://attack.mitre.org/groups/{attack_id}",
                    'stix_id': group.id,
                    'created': group.created.isoformat() if group.created else None,
                    'modified': group.modified.isoformat() if group.modified else None
                }
            
            print(f"      ✅ Loaded {len(self.threat_actors)} threat actors")
            logger.info(f"Loaded {len(self.threat_actors)} threat actors")
            
        except Exception as e:
            logger.error(f"Error loading threat actors: {e}")
    
    def _load_malware(self):
        """Load all malware from MITRE ATT&CK."""
        try:
            if not self.mitre_data:
                return
            
            software = self.mitre_data.get_software(remove_revoked_deprecated=True)
            total_software = len(software)
            
            print(f"      🦠 Loading all malware and tools...")
            print(f"      📋 Processing {total_software} malware/tools...")
            
            for i, sw in enumerate(software):
                # Show progress every 20 software
                if i % 20 == 0:
                    print(f"      Processing malware/tool {i+1}/{total_software}...")
                
                attack_id = self.mitre_data.get_attack_id(sw.id)
                if not attack_id:
                    continue
                
                # Get techniques used by this software
                sw_techniques = self.mitre_data.get_techniques_used_by_software(sw.id)
                technique_ids = []
                for tech_rel in sw_techniques:
                    tech_id = self.mitre_data.get_attack_id(tech_rel['object'].id)
                    if tech_id:
                        technique_ids.append(tech_id)
                
                # Determine software type
                sw_type = 'malware'
                if hasattr(sw, 'x_mitre_platforms') and 'PRE' in getattr(sw, 'x_mitre_platforms', []):
                    sw_type = 'tool'
                
                self.malware[attack_id] = {
                    'id': attack_id,
                    'name': sw.name,
                    'description': sw.description,
                    'type': sw_type,
                    'aliases': sw.aliases if hasattr(sw, 'aliases') else [],
                    'techniques': technique_ids,
                    'platforms': getattr(sw, 'x_mitre_platforms', []),
                    'url': f"https://attack.mitre.org/software/{attack_id}",
                    'stix_id': sw.id,
                    'created': sw.created.isoformat() if sw.created else None,
                    'modified': sw.modified.isoformat() if sw.modified else None
                }
            
            print(f"      ✅ Loaded {len(self.malware)} malware/tools")
            logger.info(f"Loaded {len(self.malware)} malware/tools")
            
        except Exception as e:
            logger.error(f"Error loading malware: {e}")
    
    def get_technique_by_id(self, technique_id: str) -> Optional[Dict]:
        """Get a specific technique by its ATT&CK ID."""
        return self.techniques.get(technique_id)
    
    def search_techniques(self, query: str) -> List[Dict]:
        """Search techniques by name or description."""
        if not query:
            return list(self.techniques.values())
        
        query_lower = query.lower()
        results = []
        
        for technique in self.techniques.values():
            if (query_lower in technique['name'].lower() or 
                query_lower in technique['description'].lower() or
                query_lower in technique['id'].lower()):
                results.append(technique)
        
        return results
    
    def get_tactic_techniques(self, tactic_id: str) -> List[Dict]:
        """Get all techniques for a specific tactic."""
        results = []
        
        # First, try to find the tactic to get its shortname
        tactic_shortname = None
        for tactic in self.tactics.values():
            if tactic.get('id') == tactic_id or tactic.get('shortname') == tactic_id:
                tactic_shortname = tactic.get('shortname')
                break
        
        print(f"DEBUG: Looking for techniques for tactic '{tactic_id}', found shortname: '{tactic_shortname}'")
        
        for technique in self.techniques.values():
            # Check if technique belongs to this tactic
            if (technique.get('tactic') == tactic_id or 
                technique.get('tactic') == tactic_shortname or
                technique.get('tactic_shortname') == tactic_id or
                technique.get('tactic_shortname') == tactic_shortname):
                results.append(technique)
        
        print(f"DEBUG: Found {len(results)} techniques for tactic '{tactic_id}'")
        return results
    
    def get_threat_actor_techniques(self, actor_id: str) -> List[Dict]:
        """Get all techniques used by a specific threat actor."""
        actor = self.threat_actors.get(actor_id)
        if not actor:
            return []
        
        results = []
        for tech_id in actor.get('techniques', []):
            technique = self.techniques.get(tech_id)
            if technique:
                results.append(technique)
        
        return results
    
    def get_attack_matrix(self) -> Dict:
        """Get the complete ATT&CK matrix structure."""
        matrix = {
            'tactics': [],
            'techniques_by_tactic': {}
        }
        
        # Add tactics
        for tactic in self.tactics.values():
            matrix['tactics'].append(tactic)
            matrix['techniques_by_tactic'][tactic['shortname']] = []
        
        # Add techniques to their tactics
        for technique in self.techniques.values():
            tactic_shortname = technique['tactic']
            if tactic_shortname in matrix['techniques_by_tactic']:
                matrix['techniques_by_tactic'][tactic_shortname].append(technique)
        
        return matrix
    
    def get_all_techniques(self) -> List[Dict]:
        """Get all techniques."""
        return list(self.techniques.values())
    
    def get_all_tactics(self) -> List[Dict]:
        """Get all tactics."""
        return list(self.tactics.values())
    
    def get_all_threat_actors(self) -> List[Dict]:
        """Get all threat actors."""
        return list(self.threat_actors.values())
    
    def get_all_malware(self) -> List[Dict]:
        """Get all malware and tools."""
        return list(self.malware.values())
    
    def calculate_threat_score(self, mapped_techniques: List[Dict]) -> int:
        """Calculate threat score based on mapped techniques."""
        if not mapped_techniques:
            return 0
        
        # Base score from number of techniques
        base_score = min(len(mapped_techniques) * 10, 50)
        
        # Additional score from high-impact techniques
        high_impact_techniques = [
            'T1055',  # Process Injection
            'T1071',  # Application Layer Protocol
            'T1078',  # Valid Accounts
            'T1083',  # File and Directory Discovery
            'T1059',  # Command and Scripting Interpreter
        ]
        
        impact_bonus = 0
        for technique in mapped_techniques:
            if technique.get('id') in high_impact_techniques:
                impact_bonus += 5
        
        return min(base_score + impact_bonus, 100)
    
    def clear_cache(self):
        """Clear the cache and force a fresh load."""
        try:
            if os.path.exists(self.cache_file):
                os.remove(self.cache_file)
                print("      🗑️  Cache cleared")
            
            # Reset all data
            self.techniques = {}
            self.tactics = {}
            self.threat_actors = {}
            self.malware = {}
            
            # Force fresh load
            self._load_attack_data()
            
        except Exception as e:
            print(f"      ❌ Error clearing cache: {e}")
            logger.error(f"Error clearing cache: {e}")
    
    def get_cache_status(self) -> Dict:
        """Get cache status information."""
        return {
            'cache_file_exists': os.path.exists(self.cache_file),
            'techniques_count': len(self.techniques),
            'tactics_count': len(self.tactics),
            'threat_actors_count': len(self.threat_actors),
            'malware_count': len(self.malware),
            'cache_file_size': os.path.getsize(self.cache_file) if os.path.exists(self.cache_file) else 0
        }

def get_mitre_attack():
    """Get MITRE ATT&CK integration instance."""
    return MitreAttackIntegration() 