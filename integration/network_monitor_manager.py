import logging
import threading
import time
import os
import sys
import psutil
from typing import Dict, List, Optional
from datetime import datetime

# Add parent directory to path to import network monitoring components
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from network_monitoring.connection_monitor import ConnectionMonitor
from network_monitoring.process_monitor import ProcessMonitor
from network_monitoring.threat_detector import ThreatDetector
from network_monitoring.yara_scanner import YaraScanner
from integration.event_correlator import EventCorrelator
from integration.unified_alerter import UnifiedAlerter, AlertType, AlertSeverity

logger = logging.getLogger(__name__)

class NetworkMonitorManager:
    """Manages network monitoring and threat intelligence integration."""
    
    def __init__(self, api_keys: Dict[str, str], socketio=None):
        """Initialize the network monitor manager."""
        self.api_keys = api_keys
        self.socketio = socketio
        self.is_running = False
        self.monitor_thread = None
        
        # Initialize components
        self.connection_monitor = ConnectionMonitor()
        self.process_monitor = ProcessMonitor()
        self.threat_detector = ThreatDetector()
        self.yara_scanner = YaraScanner()
        
        # Initialize integration components
        self.event_correlator = EventCorrelator(api_keys)
        self.unified_alerter = UnifiedAlerter()
        
        # Add alert handler for real-time updates
        if self.socketio:
            self.unified_alerter.add_alert_handler(self._socketio_alert_handler)
        
        # Statistics
        self.stats = {
            'start_time': None,
            'connections_analyzed': 0,
            'processes_analyzed': 0,
            'alerts_generated': 0,
            'threat_intel_queries': 0,
            'last_update': None
        }
        
        logger.info("Network Monitor Manager initialized")
    
    def start_monitoring(self):
        """Start all monitoring components."""
        if self.is_running:
            logger.warning("Network monitoring already running")
            return
        
        try:
            self.is_running = True
            self.stats['start_time'] = datetime.now().isoformat()
            
            # Start individual monitors
            self.connection_monitor.start_monitoring(interval=1.0)
            self.process_monitor.start_monitoring()
            
            # Start the main monitoring thread
            self.monitor_thread = threading.Thread(
                target=self._monitoring_loop,
                daemon=True
            )
            self.monitor_thread.start()
            
            logger.info("Network monitoring started successfully")
            
        except Exception as e:
            logger.error(f"Error starting network monitoring: {e}")
            self.is_running = False
            raise
    
    def stop_monitoring(self):
        """Stop all monitoring components."""
        if not self.is_running:
            return
        
        try:
            self.is_running = False
            
            # Stop individual monitors
            self.connection_monitor.stop_monitoring()
            self.process_monitor.stop_monitoring()
            
            # Wait for monitoring thread to finish
            if self.monitor_thread:
                self.monitor_thread.join(timeout=5.0)
            
            logger.info("Network monitoring stopped")
            
        except Exception as e:
            logger.error(f"Error stopping network monitoring: {e}")
    
    def _monitoring_loop(self):
        """Main monitoring loop that correlates events and generates alerts."""
        while self.is_running:
            try:
                # Get current monitoring data
                connections = self.connection_monitor.get_connections()
                processes = self.process_monitor.get_processes()
                
                # Analyze connections
                self._analyze_connections(connections)
                
                # Analyze processes
                self._analyze_processes(processes)
                
                # Update statistics
                self.stats['last_update'] = datetime.now().isoformat()
                
                # Emit updates via SocketIO if available
                if self.socketio:
                    self._emit_monitoring_updates(connections, processes)
                
                time.sleep(2.0)  # Update every 2 seconds
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(5.0)  # Wait longer on error
    
    def _analyze_connections(self, connections: List[Dict]):
        """Analyze network connections and correlate with threat intelligence."""
        for connection in connections:
            try:
                self.stats['connections_analyzed'] += 1
                
                # Correlate connection with threat intelligence
                correlation_result = self.event_correlator.correlate_connection_event(connection)
                
                # Check if correlation indicates a threat
                if correlation_result.get('threat_score', 0) > 0:
                    self.stats['threat_intel_queries'] += 1
                    
                    # Create alert if threshold is met
                    alert = self.unified_alerter.create_network_connection_alert(
                        connection, correlation_result.get('threat_intelligence', {})
                    )
                    
                    if alert:
                        self.stats['alerts_generated'] += 1
                        logger.info(f"Network connection alert created: {alert['id']}")
                
            except Exception as e:
                logger.error(f"Error analyzing connection: {e}")
    
    def _analyze_processes(self, processes: List[Dict]):
        """Analyze processes and correlate with threat intelligence."""
        for process in processes:
            try:
                self.stats['processes_analyzed'] += 1
                
                # Get YARA scan results for the process
                yara_results = []
                if process.get('pid'):
                    yara_result = self.yara_scanner.scan_process(process['pid'])
                    if yara_result:
                        yara_results.append(yara_result)
                
                # Check if process is suspicious
                if yara_results or process.get('suspicious_factors'):
                    # Correlate process with threat intelligence
                    correlation_result = self.event_correlator.correlate_process_event(process)
                    
                    # Create alert for suspicious process
                    alert = self.unified_alerter.create_suspicious_process_alert(
                        process, yara_results
                    )
                    
                    if alert:
                        self.stats['alerts_generated'] += 1
                        logger.info(f"Suspicious process alert created: {alert['id']}")
                
            except Exception as e:
                logger.error(f"Error analyzing process: {e}")
    
    def _emit_monitoring_updates(self, connections: List[Dict], processes: List[Dict]):
        """Emit monitoring updates via SocketIO."""
        try:
            # Get current statistics
            connection_stats = self.connection_monitor.get_stats()
            alert_stats = self.unified_alerter.get_alert_statistics()
            
            # Combine monitoring data
            monitoring_data = {
                'connections': connections,
                'connection_stats': connection_stats,
                'processes': processes,
                'alerts': self.unified_alerter.get_alerts({'resolved': False}),
                'alert_stats': alert_stats,
                'manager_stats': self.stats,
                'timestamp': datetime.now().isoformat()
            }
            
            # Emit via SocketIO
            self.socketio.emit('monitoring_update', monitoring_data)
            
        except Exception as e:
            logger.error(f"Error emitting monitoring updates: {e}")
    
    def _socketio_alert_handler(self, alert: Dict):
        """Handle new alerts by emitting them via SocketIO."""
        try:
            if self.socketio:
                self.socketio.emit('new_alert', alert)
        except Exception as e:
            logger.error(f"Error in SocketIO alert handler: {e}")
    
    def get_monitoring_data(self) -> Dict:
        """Get current monitoring data."""
        try:
            connections = self.connection_monitor.get_connections()
            processes = self.process_monitor.get_processes()
            connection_stats = self.connection_monitor.get_stats()
            alert_stats = self.unified_alerter.get_alert_statistics()
            
            return {
                'connections': connections,
                'connection_stats': connection_stats,
                'processes': processes,
                'alerts': self.unified_alerter.get_alerts({'resolved': False}),
                'alert_stats': alert_stats,
                'manager_stats': self.stats,
                'correlation_cache_stats': self.event_correlator.get_cache_stats(),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting monitoring data: {e}")
            return {}
    
    def get_process_statistics(self) -> Dict:
        """Get process monitoring statistics."""
        try:
            return self.process_monitor.get_stats()
        except Exception as e:
            logger.error(f"Error getting process statistics: {e}")
            return {}
    
    def get_alerts(self, filters: Optional[Dict] = None) -> List[Dict]:
        """Get alerts with optional filtering."""
        return self.unified_alerter.get_alerts(filters)
    
    def acknowledge_alert(self, alert_id: str, user: str = "system") -> bool:
        """Acknowledge an alert."""
        return self.unified_alerter.acknowledge_alert(alert_id, user)
    
    def resolve_alert(self, alert_id: str, user: str = "system", resolution_notes: str = "") -> bool:
        """Resolve an alert."""
        return self.unified_alerter.resolve_alert(alert_id, user, resolution_notes)
    
    def acknowledge_all_alerts(self, user: str = "system") -> bool:
        """Acknowledge all unacknowledged alerts."""
        try:
            alerts = self.unified_alerter.get_alerts({'acknowledged': False})
            for alert in alerts:
                self.unified_alerter.acknowledge_alert(alert['id'], user)
            logger.info(f"All alerts acknowledged by {user}")
            return True
        except Exception as e:
            logger.error(f"Error acknowledging all alerts: {e}")
            return False
    
    def clear_all_alerts(self) -> bool:
        """Clear all alerts."""
        try:
            self.unified_alerter.clear_alerts()
            logger.info("All alerts cleared")
            return True
        except Exception as e:
            logger.error(f"Error clearing all alerts: {e}")
            return False
    
    def clear_correlation_cache(self):
        """Clear the correlation cache."""
        self.event_correlator.clear_cache()
    
    def get_system_scan_results(self) -> List[Dict]:
        """Get results from a full system scan."""
        try:
            return self.threat_detector.scan_system()
        except Exception as e:
            logger.error(f"Error getting system scan results: {e}")
            return []
    
    def get_suspicious_processes(self) -> List[Dict]:
        """Get list of suspicious processes."""
        try:
            return self.threat_detector.get_suspicious_processes()
        except Exception as e:
            logger.error(f"Error getting suspicious processes: {e}")
            return []
    
    def kill_process(self, pid: int) -> bool:
        """Kill a process by PID."""
        try:
            process = psutil.Process(pid)
            process.terminate()
            logger.info(f"Process {pid} terminated")
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.error(f"Error killing process {pid}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error killing process {pid}: {e}")
            return False
    
    def get_process_details(self, pid: int) -> Optional[Dict]:
        """Get detailed information about a specific process."""
        try:
            return self.process_monitor.get_process_details(pid)
        except Exception as e:
            logger.error(f"Error getting process details for {pid}: {e}")
            return None
    
    def export_alerts(self, filepath: str, format: str = 'json') -> bool:
        """Export alerts to file."""
        return self.unified_alerter.export_alerts(filepath, format)
    
    def get_status(self) -> Dict:
        """Get the current status of all monitoring components."""
        return {
            'is_running': self.is_running,
            'connection_monitor': self.connection_monitor.is_running if hasattr(self.connection_monitor, 'is_running') else False,
            'process_monitor': self.process_monitor.is_running if hasattr(self.process_monitor, 'is_running') else False,
            'stats': self.stats,
            'alert_stats': self.unified_alerter.get_alert_statistics(),
            'correlation_cache_stats': self.event_correlator.get_cache_stats()
        } 