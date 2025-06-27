import logging
import threading
import time
from typing import Dict, List, Optional, Callable
from datetime import datetime, timedelta
from enum import Enum
import json
import os

logger = logging.getLogger(__name__)

class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AlertType(Enum):
    """Alert types."""
    NETWORK_CONNECTION = "network_connection"
    SUSPICIOUS_PROCESS = "suspicious_process"
    YARA_MATCH = "yara_match"
    THREAT_INTEL_MATCH = "threat_intel_match"
    CORRELATED_THREAT = "correlated_threat"
    SYSTEM_ANOMALY = "system_anomaly"

class UnifiedAlerter:
    """Unified alerting system for network monitoring and threat intelligence."""
    
    def __init__(self, alert_handlers: Optional[List[Callable]] = None):
        """Initialize the unified alerter."""
        self.alerts = []
        self.alert_handlers = alert_handlers or []
        self.alert_counters = {
            'total': 0,
            'by_severity': {severity.value: 0 for severity in AlertSeverity},
            'by_type': {alert_type.value: 0 for alert_type in AlertType}
        }
        self.max_alerts = 1000  # Keep last 1000 alerts
        self.lock = threading.Lock()
        
        # Alert thresholds
        self.thresholds = {
            'high_threat_score': 80,
            'medium_threat_score': 50,
            'low_threat_score': 30,
            'suspicious_connections': 10,
            'suspicious_processes': 5
        }
        
        # Alert rules
        self.alert_rules = self._initialize_alert_rules()
        
    def _initialize_alert_rules(self) -> Dict:
        """Initialize alert rules."""
        return {
            'network_connection': {
                'enabled': True,
                'min_threat_score': 30,
                'suspicious_ports': [22, 23, 3389, 445, 1433, 3306, 5432, 27017, 4444, 8080],
                'suspicious_ips': set()  # Can be populated with known bad IPs
            },
            'suspicious_process': {
                'enabled': True,
                'min_risk_level': 'medium',
                'yara_match_threshold': 1
            },
            'threat_intel_match': {
                'enabled': True,
                'min_threat_score': 40,
                'sources': ['abuseipdb', 'virustotal', 'shodan', 'httpbl']
            },
            'correlated_threat': {
                'enabled': True,
                'min_correlation_score': 50
            }
        }
    
    def create_alert(self, alert_type: AlertType, data: Dict, severity: AlertSeverity = AlertSeverity.MEDIUM) -> Dict:
        """Create a new alert."""
        try:
            with self.lock:
                alert = {
                    'id': self._generate_alert_id(),
                    'type': alert_type.value,
                    'severity': severity.value,
                    'data': data,
                    'timestamp': datetime.now().isoformat(),
                    'acknowledged': False,
                    'resolved': False,
                    'notes': []
                }
                
                # Add alert to list
                self.alerts.append(alert)
                
                # Update counters
                self.alert_counters['total'] += 1
                self.alert_counters['by_severity'][severity.value] += 1
                self.alert_counters['by_type'][alert_type.value] += 1
                
                # Trim old alerts if needed
                if len(self.alerts) > self.max_alerts:
                    self.alerts = self.alerts[-self.max_alerts:]
                
                # Notify handlers
                self._notify_handlers(alert)
                
                logger.info(f"Created {severity.value} alert: {alert_type.value} - {alert['id']}")
                return alert
                
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
            return {}
    
    def create_network_connection_alert(self, connection_data: Dict, threat_data: Dict) -> Optional[Dict]:
        """Create alert for suspicious network connection."""
        if not self.alert_rules['network_connection']['enabled']:
            return None
        
        # Check if IP is in whitelist
        remote_ip = connection_data.get('remote_address')
        if self._is_whitelisted_ip(remote_ip):
            return None
        
        threat_score = threat_data.get('threat_score', 0)
        if threat_score < self.alert_rules['network_connection']['min_threat_score']:
            return None
        
        # Determine severity based on threat score
        severity = self._determine_severity_from_threat_score(threat_score)
        
        # Check for suspicious ports
        remote_port = connection_data.get('remote_port')
        suspicious_ports = self.alert_rules['network_connection']['suspicious_ports']
        
        alert_data = {
            'connection': connection_data,
            'threat_intelligence': threat_data,
            'threat_score': threat_score,
            'suspicious_port': remote_port in suspicious_ports if remote_port else False
        }
        
        return self.create_alert(AlertType.NETWORK_CONNECTION, alert_data, severity)
    
    def _is_whitelisted_ip(self, ip_address: str) -> bool:
        """Check if IP address is in the whitelist of known legitimate services."""
        if not ip_address:
            return False
        
        # Known legitimate services and CDN providers
        whitelisted_ranges = [
            # Cloudflare
            '104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', '104.22.', '104.23.', '104.24.', '104.25.', '104.26.', '104.27.', '104.28.', '104.29.', '104.30.', '104.31.',
            # Google
            '8.8.8.', '8.8.4.', '142.250.', '172.217.', '216.58.',
            # Microsoft
            '13.64.', '13.65.', '13.66.', '13.67.', '13.68.', '13.69.', '13.70.', '13.71.', '13.72.', '13.73.', '13.74.', '13.75.', '13.76.', '13.77.', '13.78.', '13.79.',
            # Amazon AWS
            '52.', '54.', '18.', '35.',
            # Apple
            '17.', '104.244.',
            # Local networks
            '127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
        ]
        
        return any(ip_address.startswith(range_prefix) for range_prefix in whitelisted_ranges)
    
    def create_suspicious_process_alert(self, process_data: Dict, yara_results: List[Dict]) -> Optional[Dict]:
        """Create alert for suspicious process."""
        if not self.alert_rules['suspicious_process']['enabled']:
            return None
        
        # Check YARA matches
        yara_matches = len(yara_results) if yara_results else 0
        if yara_matches < self.alert_rules['suspicious_process']['yara_match_threshold']:
            return None
        
        # Determine severity based on YARA matches and process behavior
        severity = AlertSeverity.HIGH if yara_matches > 2 else AlertSeverity.MEDIUM
        
        alert_data = {
            'process': process_data,
            'yara_matches': yara_results,
            'match_count': yara_matches,
            'suspicious_factors': process_data.get('suspicious_factors', [])
        }
        
        return self.create_alert(AlertType.SUSPICIOUS_PROCESS, alert_data, severity)
    
    def create_threat_intel_alert(self, threat_data: Dict) -> Optional[Dict]:
        """Create alert for threat intelligence match."""
        if not self.alert_rules['threat_intel_match']['enabled']:
            return None
        
        threat_score = threat_data.get('threat_score', 0)
        if threat_score < self.alert_rules['threat_intel_match']['min_threat_score']:
            return None
        
        # Determine severity based on threat score
        severity = self._determine_severity_from_threat_score(threat_score)
        
        alert_data = {
            'threat_intelligence': threat_data,
            'threat_score': threat_score,
            'sources': list(threat_data.get('sources', {}).keys())
        }
        
        return self.create_alert(AlertType.THREAT_INTEL_MATCH, alert_data, severity)
    
    def create_correlated_threat_alert(self, correlation_result: Dict) -> Optional[Dict]:
        """Create alert for correlated threat."""
        if not self.alert_rules['correlated_threat']['enabled']:
            return None
        
        threat_score = correlation_result.get('threat_score', 0)
        if threat_score < self.alert_rules['correlated_threat']['min_correlation_score']:
            return None
        
        # Determine severity based on correlation score
        severity = self._determine_severity_from_threat_score(threat_score)
        
        alert_data = {
            'correlation': correlation_result,
            'event_type': correlation_result.get('event', {}).get('type', 'unknown'),
            'threat_score': threat_score,
            'risk_level': correlation_result.get('risk_level', 'unknown')
        }
        
        return self.create_alert(AlertType.CORRELATED_THREAT, alert_data, severity)
    
    def _determine_severity_from_threat_score(self, threat_score: int) -> AlertSeverity:
        """Determine alert severity from threat score."""
        if threat_score >= 90:
            return AlertSeverity.CRITICAL
        elif threat_score >= 70:
            return AlertSeverity.HIGH
        elif threat_score >= 50:
            return AlertSeverity.MEDIUM
        elif threat_score >= 20:
            return AlertSeverity.LOW
        else:
            return AlertSeverity.INFO
    
    def _generate_alert_id(self) -> str:
        """Generate unique alert ID."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        counter = self.alert_counters['total']
        return f"ALERT_{timestamp}_{counter:04d}"
    
    def _notify_handlers(self, alert: Dict):
        """Notify all registered alert handlers."""
        for handler in self.alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                logger.error(f"Error in alert handler: {e}")
    
    def add_alert_handler(self, handler: Callable):
        """Add a new alert handler."""
        self.alert_handlers.append(handler)
        logger.info("Alert handler added")
    
    def get_alerts(self, filters: Optional[Dict] = None) -> List[Dict]:
        """Get alerts with optional filtering."""
        with self.lock:
            alerts = self.alerts.copy()
        
        if not filters:
            return alerts
        
        filtered_alerts = []
        for alert in alerts:
            if self._matches_filters(alert, filters):
                filtered_alerts.append(alert)
        
        return filtered_alerts
    
    def _matches_filters(self, alert: Dict, filters: Dict) -> bool:
        """Check if alert matches filters."""
        for key, value in filters.items():
            if key == 'severity' and alert.get('severity') != value:
                return False
            elif key == 'type' and alert.get('type') != value:
                return False
            elif key == 'acknowledged' and alert.get('acknowledged') != value:
                return False
            elif key == 'resolved' and alert.get('resolved') != value:
                return False
            elif key == 'date_from':
                alert_date = datetime.fromisoformat(alert['timestamp'])
                if alert_date < datetime.fromisoformat(value):
                    return False
            elif key == 'date_to':
                alert_date = datetime.fromisoformat(alert['timestamp'])
                if alert_date > datetime.fromisoformat(value):
                    return False
        
        return True
    
    def acknowledge_alert(self, alert_id: str, user: str = "system") -> bool:
        """Acknowledge an alert."""
        with self.lock:
            for alert in self.alerts:
                if alert['id'] == alert_id:
                    alert['acknowledged'] = True
                    alert['notes'].append({
                        'timestamp': datetime.now().isoformat(),
                        'user': user,
                        'action': 'acknowledged'
                    })
                    logger.info(f"Alert {alert_id} acknowledged by {user}")
                    return True
        return False
    
    def resolve_alert(self, alert_id: str, user: str = "system", resolution_notes: str = "") -> bool:
        """Resolve an alert."""
        with self.lock:
            for alert in self.alerts:
                if alert['id'] == alert_id:
                    alert['resolved'] = True
                    alert['notes'].append({
                        'timestamp': datetime.now().isoformat(),
                        'user': user,
                        'action': 'resolved',
                        'notes': resolution_notes
                    })
                    logger.info(f"Alert {alert_id} resolved by {user}")
                    return True
        return False
    
    def get_alert_statistics(self) -> Dict:
        """Get alert statistics."""
        with self.lock:
            stats = self.alert_counters.copy()
            
            # Add current counts
            stats['current_alerts'] = len(self.alerts)
            stats['unacknowledged'] = len([a for a in self.alerts if not a['acknowledged']])
            stats['unresolved'] = len([a for a in self.alerts if not a['resolved']])
            
            # Add recent activity
            recent_alerts = [a for a in self.alerts 
                           if (datetime.now() - datetime.fromisoformat(a['timestamp'])).seconds < 3600]
            stats['alerts_last_hour'] = len(recent_alerts)
            
            return stats
    
    def export_alerts(self, filepath: str, format: str = 'json') -> bool:
        """Export alerts to file."""
        try:
            with self.lock:
                alerts = self.alerts.copy()
            
            if format.lower() == 'json':
                with open(filepath, 'w') as f:
                    json.dump(alerts, f, indent=2)
            else:
                logger.error(f"Unsupported export format: {format}")
                return False
            
            logger.info(f"Exported {len(alerts)} alerts to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting alerts: {e}")
            return False
    
    def clear_alerts(self, older_than_days: Optional[int] = None):
        """Clear alerts, optionally older than specified days."""
        with self.lock:
            if older_than_days is None:
                self.alerts.clear()
                logger.info("All alerts cleared")
            else:
                cutoff_date = datetime.now() - timedelta(days=older_than_days)
                original_count = len(self.alerts)
                self.alerts = [a for a in self.alerts 
                              if datetime.fromisoformat(a['timestamp']) > cutoff_date]
                cleared_count = original_count - len(self.alerts)
                logger.info(f"Cleared {cleared_count} alerts older than {older_than_days} days") 