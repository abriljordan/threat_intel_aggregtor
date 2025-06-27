import logging
import threading
import time
from typing import Dict, List, Optional
from datetime import datetime
import sys
import os

# Add parent directory to path to import API clients
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api_clients.abuseipdb_client import AbuseIPDBClient
from api_clients.virustotal_client import VirusTotalClient
from api_clients.shodan_client import ShodanClient
from api_clients.httpbl_client import HttpBLClient

logger = logging.getLogger(__name__)

class EventCorrelator:
    """Correlates local network events with external threat intelligence."""
    
    def __init__(self, api_keys: Dict[str, str]):
        """Initialize the event correlator with API keys."""
        self.api_keys = api_keys
        self.cache = {}  # Simple cache for API results
        self.cache_ttl = 300  # 5 minutes cache TTL
        self.cache_timestamps = {}
        
        # Initialize API clients
        self.abuseipdb_client = None
        self.virustotal_client = None
        self.shodan_client = None
        self.httpbl_client = None
        
        self._initialize_clients()
        
    def _initialize_clients(self):
        """Initialize threat intelligence API clients."""
        try:
            if self.api_keys.get('ABUSEIPDB_API_KEY'):
                self.abuseipdb_client = AbuseIPDBClient(self.api_keys['ABUSEIPDB_API_KEY'])
                logger.info("AbuseIPDB client initialized")
                
            if self.api_keys.get('VIRUSTOTAL_API_KEY'):
                self.virustotal_client = VirusTotalClient(self.api_keys['VIRUSTOTAL_API_KEY'])
                logger.info("VirusTotal client initialized")
                
            if self.api_keys.get('SHODAN_API_KEY'):
                self.shodan_client = ShodanClient(self.api_keys['SHODAN_API_KEY'])
                logger.info("Shodan client initialized")
                
            if self.api_keys.get('HTTPBL_ACCESS_KEY'):
                self.httpbl_client = HttpBLClient(self.api_keys['HTTPBL_ACCESS_KEY'])
                logger.info("HttpBL client initialized")
                
        except Exception as e:
            logger.error(f"Error initializing API clients: {e}")
    
    def correlate_connection_event(self, connection_data: Dict) -> Dict:
        """Correlate a network connection event with threat intelligence."""
        try:
            remote_ip = connection_data.get('remote_address')
            if not remote_ip or remote_ip in ['127.0.0.1', 'localhost', '::1']:
                return self._create_correlation_result(connection_data, {}, 'local')
            
            # Check cache first
            cache_key = f"ip_{remote_ip}"
            if self._is_cache_valid(cache_key):
                threat_data = self.cache[cache_key]
            else:
                threat_data = self._enrich_ip_with_threat_intel(remote_ip)
                self._cache_result(cache_key, threat_data)
            
            return self._create_correlation_result(connection_data, threat_data, 'correlated')
            
        except Exception as e:
            logger.error(f"Error correlating connection event: {e}")
            return self._create_correlation_result(connection_data, {}, 'error')
    
    def correlate_process_event(self, process_data: Dict) -> Dict:
        """Correlate a process event with threat intelligence."""
        try:
            # Check if process has network connections
            connections = process_data.get('connections', [])
            threat_data = {}
            
            for conn in connections:
                remote_ip = conn.get('remote_address')
                if remote_ip and remote_ip not in ['127.0.0.1', 'localhost', '::1']:
                    # Check cache first
                    cache_key = f"ip_{remote_ip}"
                    if self._is_cache_valid(cache_key):
                        ip_threat_data = self.cache[cache_key]
                    else:
                        ip_threat_data = self._enrich_ip_with_threat_intel(remote_ip)
                        self._cache_result(cache_key, ip_threat_data)
                    
                    # Merge threat data
                    threat_data = self._merge_threat_data(threat_data, ip_threat_data)
            
            return self._create_correlation_result(process_data, threat_data, 'correlated')
            
        except Exception as e:
            logger.error(f"Error correlating process event: {e}")
            return self._create_correlation_result(process_data, {}, 'error')
    
    def _enrich_ip_with_threat_intel(self, ip_address: str) -> Dict:
        """Enrich an IP address with threat intelligence data."""
        threat_data = {
            'ip_address': ip_address,
            'timestamp': datetime.now().isoformat(),
            'sources': {}
        }
        
        # Check AbuseIPDB
        if self.abuseipdb_client:
            try:
                abuse_result = self.abuseipdb_client.check_ip(ip_address)
                if 'data' in abuse_result:
                    threat_data['sources']['abuseipdb'] = abuse_result['data']
                elif 'error' in abuse_result:
                    threat_data['sources']['abuseipdb'] = {'error': abuse_result['error']}
            except Exception as e:
                logger.error(f"AbuseIPDB error for {ip_address}: {e}")
                threat_data['sources']['abuseipdb'] = {'error': str(e)}
        
        # Check VirusTotal
        if self.virustotal_client:
            try:
                vt_result = self.virustotal_client.check_ip(ip_address)
                if 'data' in vt_result:
                    threat_data['sources']['virustotal'] = vt_result['data']
                elif 'error' in vt_result:
                    threat_data['sources']['virustotal'] = {'error': vt_result['error']}
            except Exception as e:
                logger.error(f"VirusTotal error for {ip_address}: {e}")
                threat_data['sources']['virustotal'] = {'error': str(e)}
        
        # Check Shodan
        if self.shodan_client:
            try:
                shodan_result = self.shodan_client.check_ip(ip_address)
                if 'data' in shodan_result:
                    threat_data['sources']['shodan'] = shodan_result['data']
                elif 'error' in shodan_result:
                    threat_data['sources']['shodan'] = {'error': shodan_result['error']}
            except Exception as e:
                logger.error(f"Shodan error for {ip_address}: {e}")
                threat_data['sources']['shodan'] = {'error': str(e)}
        
        # Check HttpBL
        if self.httpbl_client:
            try:
                httpbl_result = self.httpbl_client.check_ip(ip_address)
                threat_data['sources']['httpbl'] = httpbl_result
            except Exception as e:
                logger.error(f"HttpBL error for {ip_address}: {e}")
                threat_data['sources']['httpbl'] = {'error': str(e)}
        
        # Calculate overall threat score
        threat_data['threat_score'] = self._calculate_threat_score(threat_data['sources'])
        threat_data['risk_level'] = self._determine_risk_level(threat_data['threat_score'])
        
        return threat_data
    
    def _calculate_threat_score(self, sources: Dict) -> int:
        """Calculate overall threat score from multiple sources."""
        score = 0
        
        # AbuseIPDB scoring
        if 'abuseipdb' in sources and 'data' in sources['abuseipdb']:
            abuse_data = sources['abuseipdb']['data']
            if 'abuseConfidenceScore' in abuse_data:
                score += abuse_data['abuseConfidenceScore']
        
        # VirusTotal scoring
        if 'virustotal' in sources and 'data' in sources['virustotal']:
            vt_data = sources['virustotal']['data']
            if 'attributes' in vt_data:
                stats = vt_data['attributes'].get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                score += malicious * 10  # 10 points per malicious detection
        
        # Shodan scoring
        if 'shodan' in sources and 'data' in sources['shodan']:
            shodan_data = sources['shodan']['data']
            if 'vulns' in shodan_data and shodan_data['vulns']:
                score += len(shodan_data['vulns']) * 15  # 15 points per vulnerability
        
        # HttpBL scoring
        if 'httpbl' in sources and sources['httpbl'].get('listed'):
            score += sources['httpbl'].get('threat_score', 0)
        
        return min(score, 100)  # Cap at 100
    
    def _determine_risk_level(self, threat_score: int) -> str:
        """Determine risk level based on threat score."""
        if threat_score >= 80:
            return 'high'
        elif threat_score >= 50:
            return 'medium'
        elif threat_score >= 20:
            return 'low'
        else:
            return 'minimal'
    
    def _create_correlation_result(self, event_data: Dict, threat_data: Dict, status: str) -> Dict:
        """Create a correlation result combining event and threat data."""
        return {
            'event': event_data,
            'threat_intelligence': threat_data,
            'correlation_status': status,
            'timestamp': datetime.now().isoformat(),
            'risk_level': threat_data.get('risk_level', 'unknown'),
            'threat_score': threat_data.get('threat_score', 0)
        }
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cached result is still valid."""
        if cache_key not in self.cache_timestamps:
            return False
        
        age = time.time() - self.cache_timestamps[cache_key]
        return age < self.cache_ttl
    
    def _cache_result(self, cache_key: str, result: Dict):
        """Cache a result with timestamp."""
        self.cache[cache_key] = result
        self.cache_timestamps[cache_key] = time.time()
    
    def _merge_threat_data(self, existing: Dict, new: Dict) -> Dict:
        """Merge threat data from multiple sources."""
        if not existing:
            return new
        
        merged = existing.copy()
        
        # Merge sources
        if 'sources' not in merged:
            merged['sources'] = {}
        
        for source, data in new.get('sources', {}).items():
            merged['sources'][source] = data
        
        # Recalculate threat score
        merged['threat_score'] = self._calculate_threat_score(merged['sources'])
        merged['risk_level'] = self._determine_risk_level(merged['threat_score'])
        
        return merged
    
    def clear_cache(self):
        """Clear the correlation cache."""
        self.cache.clear()
        self.cache_timestamps.clear()
        logger.info("Correlation cache cleared")
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics."""
        return {
            'cache_size': len(self.cache),
            'cache_ttl': self.cache_ttl,
            'oldest_entry': min(self.cache_timestamps.values()) if self.cache_timestamps else None,
            'newest_entry': max(self.cache_timestamps.values()) if self.cache_timestamps else None
        } 