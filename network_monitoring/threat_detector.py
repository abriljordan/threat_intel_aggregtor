import psutil
import logging
import re
from typing import Dict, List, Set
from datetime import datetime
import os
import platform
from .yara_scanner import YaraScanner

# Configure logging
logger = logging.getLogger(__name__)

class ThreatDetector:
    def __init__(self):
        """Initialize threat detection system."""
        self.suspicious_patterns = {
            'process_names': {
                'crypto_miners': [
                    r'miner', r'cryptominer', r'xmrig', r'nicehash',
                    r'ethminer', r'minergate', r'coinhive'
                ],
                'malware_indicators': [
                    r'\.exe$', r'\.bat$', r'\.vbs$', r'\.ps1$',
                    r'\.sh$', r'\.py$', r'\.js$', r'\.jar$'
                ],
                'suspicious_names': [
                    r'backdoor', r'rootkit', r'keylogger', r'trojan',
                    r'botnet', r'worm', r'virus', r'malware'
                ]
            },
            'suspicious_paths': [
                r'/tmp/', r'/var/tmp/', r'/dev/shm/',
                r'~/Library/Application Support/',
                r'~/Library/Caches/',
                r'~/Downloads/'
            ],
            'suspicious_ports': {
                22, 23, 3389, 445, 1433, 3306, 5432, 27017  # Common attack ports
            },
            'suspicious_ips': set()  # Can be populated with known malicious IPs
        }
        
        # Compile regex patterns
        self.compiled_patterns = {
            'process_names': {
                category: [re.compile(pattern, re.IGNORECASE) 
                          for pattern in patterns]
                for category, patterns in self.suspicious_patterns['process_names'].items()
            },
            'suspicious_paths': [
                re.compile(pattern) for pattern in self.suspicious_patterns['suspicious_paths']
            ]
        }
        
        # Thresholds for suspicious behavior
        self.thresholds = {
            'cpu_usage': 80.0,  # Percentage
            'memory_usage': 70.0,  # Percentage
            'network_connections': 50,  # Number of connections
            'child_processes': 10  # Number of child processes
        }
        
        # Known safe processes (whitelist)
        self.whitelist = {
            'system_processes': {
                'kernel_task', 'launchd', 'WindowServer', 'Finder',
                'SystemUIServer', 'Dock', 'loginwindow', 'UserEventAgent'
            },
            'common_apps': {
                'Safari', 'Chrome', 'Firefox', 'Terminal', 'Python',
                'node', 'npm', 'VSCode', 'Xcode', 'Activity Monitor'
            }
        }
        
        # Track suspicious processes
        self.suspicious_processes: Dict[int, Dict] = {}
        
        # Initialize YARA scanner
        self.yara_scanner = YaraScanner()
        
        # Add YARA scanning results
        self.yara_results = {}
        
    def is_suspicious_process_name(self, name: str) -> bool:
        """Check if a process name matches suspicious patterns."""
        for category in self.compiled_patterns['process_names'].values():
            for pattern in category:
                if pattern.search(name):
                    return True
        return False
    
    def is_suspicious_path(self, path: str) -> bool:
        """Check if a process path is suspicious."""
        if not path:
            return False
        return any(pattern.search(path) for pattern in self.compiled_patterns['suspicious_paths'])
    
    def is_whitelisted(self, name: str) -> bool:
        """Check if a process is in the whitelist."""
        return (name in self.whitelist['system_processes'] or 
                name in self.whitelist['common_apps'])
    
    def check_process_behavior(self, proc: psutil.Process) -> Dict:
        """Analyze process behavior for suspicious patterns."""
        try:
            suspicious_factors = []
            
            # Check CPU and memory usage
            try:
                cpu_percent = proc.cpu_percent(interval=0.1)
                memory_percent = proc.memory_percent()
                
                if cpu_percent > self.thresholds['cpu_usage']:
                    suspicious_factors.append(f"High CPU usage: {cpu_percent:.1f}%")
                if memory_percent > self.thresholds['memory_usage']:
                    suspicious_factors.append(f"High memory usage: {memory_percent:.1f}%")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
            # Check number of connections
            try:
                connections = len(proc.connections())
                if connections > self.thresholds['network_connections']:
                    suspicious_factors.append(f"High number of connections: {connections}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
            # Check child processes
            try:
                children = len(proc.children())
                if children > self.thresholds['child_processes']:
                    suspicious_factors.append(f"High number of child processes: {children}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
            # Check process path
            try:
                path = proc.exe()
                if self.is_suspicious_path(path):
                    suspicious_factors.append(f"Suspicious path: {path}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
            # Check process privileges
            try:
                if os.geteuid() == 0 and proc.uids().real != 0:
                    suspicious_factors.append("Running with elevated privileges")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
            return {
                'is_suspicious': len(suspicious_factors) > 0,
                'suspicious_factors': suspicious_factors,
                'risk_level': min(len(suspicious_factors) * 2, 10)  # Risk level 0-10
            }
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.debug(f"Could not analyze process {proc.pid}: {str(e)}")
            return {'is_suspicious': False, 'suspicious_factors': [], 'risk_level': 0}
    
    def analyze_process(self, proc: psutil.Process) -> Dict:
        """Analyze a process for potential threats."""
        try:
            # Skip if process is no longer running
            if not proc.is_running():
                return None
                
            # Get basic process info
            name = proc.name()
            pid = proc.pid
            
            # Skip whitelisted processes
            if self.is_whitelisted(name):
                return None
            
            # Check process name
            name_suspicious = self.is_suspicious_process_name(name)
            
            # Check process behavior
            behavior = self.check_process_behavior(proc)
            
            # Perform YARA scan
            yara_result = self.yara_scanner.scan_process(pid)
            if yara_result:
                self.yara_results[pid] = yara_result
                behavior['suspicious_factors'].extend([
                    f"YARA match: {match['rule']} ({match['meta'].get('description', 'No description')})"
                    for match in yara_result['matches']
                ])
                behavior['risk_level'] = max(
                    behavior['risk_level'],
                    {'low': 3, 'medium': 6, 'high': 9}.get(yara_result['severity'], 3)
                )
            
            # Combine results
            is_suspicious = name_suspicious or behavior['is_suspicious'] or bool(yara_result)
            suspicious_factors = behavior['suspicious_factors']
            if name_suspicious:
                suspicious_factors.append(f"Suspicious process name: {name}")
            
            if is_suspicious:
                result = {
                    'pid': pid,
                    'name': name,
                    'is_suspicious': True,
                    'suspicious_factors': suspicious_factors,
                    'risk_level': behavior['risk_level'],
                    'timestamp': datetime.now().isoformat(),
                    'yara_matches': yara_result['matches'] if yara_result else None,
                    'file_hash': yara_result['hash'] if yara_result else None
                }
                
                # Update suspicious processes tracking
                self.suspicious_processes[pid] = result
                return result
                
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.debug(f"Could not analyze process {proc.pid}: {str(e)}")
        
        return None
    
    def get_suspicious_processes(self) -> List[Dict]:
        """Get list of currently suspicious processes."""
        # Clean up terminated processes
        self.suspicious_processes = {
            pid: info for pid, info in self.suspicious_processes.items()
            if psutil.pid_exists(pid)
        }
        return list(self.suspicious_processes.values())
    
    def get_yara_results(self) -> Dict[int, Dict]:
        """Get YARA scan results for all processes."""
        return self.yara_results
    
    def scan_system(self) -> List[Dict]:
        """Perform a full system scan using YARA rules."""
        results = []
        
        # Scan common directories
        directories_to_scan = [
            os.path.expanduser('~/Downloads'),
            os.path.expanduser('~/Library/Application Support'),
            '/Applications',
            '/usr/local/bin',
            '/usr/local/sbin'
        ]
        
        for directory in directories_to_scan:
            if os.path.exists(directory):
                results.extend(self.yara_scanner.scan_directory(directory))
                
        return results

# Global instance
threat_detector = ThreatDetector() 