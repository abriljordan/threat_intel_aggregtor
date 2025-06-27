import psutil
import threading
import time
from datetime import datetime
import socket
from collections import defaultdict
import os
import hashlib
import re
import json
import requests
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class ProcessMonitor:
    def __init__(self):
        self.processes = {}  # Current process stats
        self.history = defaultdict(list)  # Historical data for charts
        self.alerts = []  # Process-related alerts
        self._lock = threading.Lock()
        self._max_history = 60  # Keep 60 seconds of history
        self._max_alerts = 100  # Keep last 100 alerts
        self.is_monitoring = False
        self._monitor_thread = None
        
        # Malware detection settings
        self.suspicious_patterns = {
            'names': [
                r'cryptominer', r'miner', r'crypto', r'coinminer',
                r'botnet', r'backdoor', r'trojan', r'keylogger',
                r'stealer', r'injector', r'rootkit', r'ransomware'
            ],
            'paths': [
                r'/tmp/', r'/var/tmp/', r'/dev/shm/',
                r'AppData/Local/Temp', r'AppData/Roaming',
                r'\.(exe|dll|bat|cmd|vbs|js|ps1)$'
            ],
            'ports': {
                22, 23, 3389, 445, 1433, 3306,  # Common attack ports
                4444, 5554, 6667, 7777, 8888,  # Common malware ports
                9999, 10000, 12345, 31337, 54321  # Suspicious ports
            },
            'behaviors': {
                'high_cpu_threshold': 90,  # CPU usage threshold
                'high_memory_threshold': 10,  # Memory usage threshold
                'suspicious_connections': 5,  # Number of suspicious connections
                'file_operations_threshold': 100  # File operations per second
            }
        }
        
        # Known malware signatures (MD5 hashes)
        self.known_malware_hashes = set()
        self._load_malware_signatures()
        
        # Process behavior tracking
        self.process_behaviors = defaultdict(lambda: {
            'file_operations': 0,
            'network_connections': 0,
            'cpu_spikes': 0,
            'memory_spikes': 0,
            'suspicious_activities': 0
        })
        
    def _load_malware_signatures(self):
        """Load known malware signatures from file."""
        try:
            signatures_file = Path('malware_signatures.json')
            if signatures_file.exists():
                with open(signatures_file, 'r') as f:
                    self.known_malware_hashes = set(json.load(f))
        except Exception as e:
            print(f"Error loading malware signatures: {e}")
            
    def start_monitoring(self):
        """Start the process monitoring thread."""
        if not self.is_monitoring:
            self.is_monitoring = True
            self._monitor_thread = threading.Thread(target=self._monitor_processes, daemon=True)
            self._monitor_thread.start()
            logger.info("Process monitoring started")
            
    def stop_monitoring(self):
        """Stop the process monitoring thread."""
        self.is_monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=1.0)
            logger.info("Process monitoring stopped")
            
    def _monitor_processes(self):
        """Monitor processes in a background thread."""
        while self.is_monitoring:
            try:
                self._update_process_stats()
                time.sleep(1)  # Update every second
            except Exception as e:
                self.add_alert(f"Error monitoring processes: {str(e)}", "error")
                time.sleep(5)  # Wait longer on error
                
    def _update_process_stats(self):
        """Update process statistics."""
        current_time = datetime.now().isoformat()  # Store as ISO format string
        current_stats = {
            'timestamp': current_time,
            'processes': [],
            'total_cpu_percent': 0,
            'total_memory_percent': 0
        }
        
        try:
            # Get all processes
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 
                                          'memory_percent', 'create_time', 'status']):
                try:
                    # Get process info
                    pinfo = proc.info
                    
                    # Get open ports for the process
                    connections = []
                    try:
                        for conn in proc.connections():
                            if conn.status == 'LISTEN':
                                connections.append({
                                    'local_port': conn.laddr.port,
                                    'local_ip': conn.laddr.ip,
                                    'status': conn.status
                                })
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        pass
                    
                    # Create process entry with ISO format timestamp
                    process_entry = {
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'username': pinfo['username'],
                        'cpu_percent': pinfo['cpu_percent'],
                        'memory_percent': pinfo['memory_percent'],
                        'create_time': datetime.fromtimestamp(pinfo['create_time']).isoformat() if pinfo['create_time'] else None,
                        'status': pinfo['status'],
                        'connections': connections
                    }
                    
                    current_stats['processes'].append(process_entry)
                    current_stats['total_cpu_percent'] += pinfo['cpu_percent']
                    current_stats['total_memory_percent'] += pinfo['memory_percent']
                    
                    # Check for suspicious behavior
                    self._check_process_behavior(process_entry)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                    
            # Sort processes by CPU usage
            current_stats['processes'].sort(key=lambda x: x['cpu_percent'], reverse=True)
            
            # Update history
            with self._lock:
                self.processes = current_stats
                self.history['cpu'].append(current_stats['total_cpu_percent'])
                self.history['memory'].append(current_stats['total_memory_percent'])
                
                # Trim history
                if len(self.history['cpu']) > self._max_history:
                    self.history['cpu'] = self.history['cpu'][-self._max_history:]
                    self.history['memory'] = self.history['memory'][-self._max_history:]
                    
        except Exception as e:
            self.add_alert(f"Error updating process stats: {str(e)}", "error")
            
    def _check_process_behavior(self, process):
        """Check for suspicious process behavior."""
        pid = process['pid']
        behavior = self.process_behaviors[pid]
        
        # Check process name against suspicious patterns
        if any(re.search(pattern, process['name'].lower()) for pattern in self.suspicious_patterns['names']):
            self.add_alert(
                f"Suspicious process name detected: {process['name']} (PID: {pid})",
                "warning"
            )
            behavior['suspicious_activities'] += 1
            
        # Check process path
        try:
            proc = psutil.Process(pid)
            exe_path = proc.exe()
            if any(re.search(pattern, exe_path) for pattern in self.suspicious_patterns['paths']):
                self.add_alert(
                    f"Process running from suspicious location: {process['name']} (PID: {pid}) at {exe_path}",
                    "warning"
                )
                behavior['suspicious_activities'] += 1
                
            # Check file hash against known malware signatures
            try:
                with open(exe_path, 'rb') as f:
                    file_hash = hashlib.md5(f.read()).hexdigest()
                    if file_hash in self.known_malware_hashes:
                        self.add_alert(
                            f"Known malware detected: {process['name']} (PID: {pid})",
                            "danger"
                        )
                        behavior['suspicious_activities'] += 3
            except (PermissionError, FileNotFoundError):
                pass
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
        # Check CPU usage
        if process['cpu_percent'] > self.suspicious_patterns['behaviors']['high_cpu_threshold']:
            behavior['cpu_spikes'] += 1
            if behavior['cpu_spikes'] >= 3:  # Multiple CPU spikes
                self.add_alert(
                    f"Persistent high CPU usage: {process['name']} (PID: {pid}) using {process['cpu_percent']}% CPU",
                    "warning"
                )
                behavior['suspicious_activities'] += 1
                
        # Check memory usage
        if process['memory_percent'] > self.suspicious_patterns['behaviors']['high_memory_threshold']:
            behavior['memory_spikes'] += 1
            if behavior['memory_spikes'] >= 3:  # Multiple memory spikes
                self.add_alert(
                    f"Persistent high memory usage: {process['name']} (PID: {pid}) using {process['memory_percent']}% memory",
                    "warning"
                )
                behavior['suspicious_activities'] += 1
                
        # Check network connections
        suspicious_ports = self.suspicious_patterns['ports']
        suspicious_conns = [conn for conn in process['connections'] 
                          if conn['local_port'] in suspicious_ports]
        
        if suspicious_conns:
            behavior['network_connections'] += len(suspicious_conns)
            if behavior['network_connections'] >= self.suspicious_patterns['behaviors']['suspicious_connections']:
                self.add_alert(
                    f"Multiple suspicious ports open: {process['name']} (PID: {pid}) using ports {[conn['local_port'] for conn in suspicious_conns]}",
                    "warning"
                )
                behavior['suspicious_activities'] += 1
                
        # Check for potential malware based on behavior score
        if behavior['suspicious_activities'] >= 3:
            self.add_alert(
                f"Potential malware detected: {process['name']} (PID: {pid}) - Multiple suspicious behaviors",
                "danger"
            )
            
        # Reset counters if process is no longer suspicious
        if behavior['suspicious_activities'] == 0:
            self.process_behaviors.pop(pid, None)
            
    def _check_file_operations(self, pid):
        """Monitor file operations for a process."""
        try:
            proc = psutil.Process(pid)
            io_counters = proc.io_counters()
            behavior = self.process_behaviors[pid]
            
            # Check for high file I/O
            if io_counters.read_bytes + io_counters.write_bytes > self.suspicious_patterns['behaviors']['file_operations_threshold']:
                behavior['file_operations'] += 1
                if behavior['file_operations'] >= 3:
                    self.add_alert(
                        f"High file I/O activity: Process {pid}",
                        "warning"
                    )
                    behavior['suspicious_activities'] += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
    def get_malware_risk_level(self, pid):
        """Get the malware risk level for a process."""
        behavior = self.process_behaviors.get(pid, {})
        suspicious_score = behavior.get('suspicious_activities', 0)
        
        if suspicious_score >= 5:
            return 'high'
        elif suspicious_score >= 3:
            return 'medium'
        elif suspicious_score >= 1:
            return 'low'
        return 'none'
        
    def get_process_details(self, pid):
        """Get detailed process information including malware risk assessment."""
        try:
            proc = psutil.Process(pid)
            process_info = self.get_process_by_pid(pid)
            if not process_info:
                return None
                
            # Add malware risk assessment
            process_info['malware_risk'] = {
                'level': self.get_malware_risk_level(pid),
                'behaviors': self.process_behaviors[pid],
                'suspicious_activities': [
                    activity for activity, count in self.process_behaviors[pid].items()
                    if count > 0
                ]
            }
            
            return process_info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
            
    def add_alert(self, message, level="info"):
        """Add an alert to the alerts list."""
        with self._lock:
            alert = {
                'timestamp': datetime.now().isoformat(),  # Store as ISO format string
                'message': message,
                'level': level
            }
            self.alerts.append(alert)
            if len(self.alerts) > self._max_alerts:
                self.alerts.pop(0)
                
    def get_stats(self):
        """Get current process statistics."""
        with self._lock:
            return {
                'processes': self.processes,
                'history': dict(self.history),
                'alerts': self.alerts.copy(),
                'is_monitoring': self.is_monitoring
            }
            
    def get_top_processes(self, limit=10):
        """Get top processes by CPU usage."""
        with self._lock:
            if not self.processes or 'processes' not in self.processes:
                return []
            return self.processes['processes'][:limit]
            
    def get_process_by_pid(self, pid):
        """Get detailed information about a specific process."""
        try:
            with self._lock:
                for proc in self.processes.get('processes', []):
                    if proc['pid'] == pid:
                        return proc
        except Exception as e:
            self.add_alert(f"Error getting process info for PID {pid}: {str(e)}", "error")
        return None

    def get_processes(self):
        """Get information about all monitored processes."""
        processes = []
        with self._lock:
            for proc in self.processes.get('processes', []):
                try:
                    processes.append({
                        'pid': proc['pid'],
                        'name': proc['name'],
                        'username': proc['username'],
                        'cpu_percent': proc['cpu_percent'],
                        'memory_percent': proc['memory_percent'],
                        'status': proc['status'],
                        'create_time': proc['create_time']
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        return processes

# Global process monitor instance
process_monitor = ProcessMonitor() 