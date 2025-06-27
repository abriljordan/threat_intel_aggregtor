import yara
import os
import logging
import hashlib
import tempfile
from typing import Dict, List, Optional, Tuple
import psutil
import platform
import subprocess
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)

class YaraScanner:
    def __init__(self):
        """Initialize YARA scanner with rules."""
        self.rules = None
        self.rules_path = os.path.join(os.path.dirname(__file__), 'yara_rules')
        self.scan_results: Dict[str, Dict] = {}
        self.last_scan = None
        
        # Create rules directory if it doesn't exist
        os.makedirs(self.rules_path, exist_ok=True)
        
        # Initialize with some basic rules
        if not self._initialize_rules():
            logger.error("Failed to initialize YARA rules. Scanner will not be functional.")
        
    def _initialize_rules(self) -> bool:
        """Initialize basic YARA rules for common malware patterns."""
        try:
            basic_rules = """
            rule SuspiciousProcess {
                meta:
                    description = "Detects suspicious process names and patterns"
                    severity = "high"
                    category = "malware"
                strings:
                    $a = "miner" nocase
                    $b = "cryptominer" nocase
                    $c = "backdoor" nocase
                    $d = "rootkit" nocase
                    $e = "keylogger" nocase
                    $f = "trojan" nocase
                    $g = "botnet" nocase
                    $h = "worm" nocase
                    $i = "virus" nocase
                    $j = "malware" nocase
                    $k = "exploit" nocase
                    $l = "payload" nocase
                    $m = "inject" nocase
                    $n = "shellcode" nocase
                    $o = "ransomware" nocase
                condition:
                    3 of them
            }

            rule SuspiciousBehavior {
                meta:
                    description = "Detects suspicious process behavior"
                    severity = "medium"
                    category = "malware"
                strings:
                    $a = "CreateRemoteThread" wide ascii
                    $b = "VirtualAllocEx" wide ascii
                    $c = "WriteProcessMemory" wide ascii
                    $d = "cmd.exe /c" wide ascii
                    $e = "powershell.exe -enc" wide ascii
                    $f = "certutil.exe -urlcache" wide ascii
                    $g = "bitsadmin.exe /transfer" wide ascii
                    $h = "regsvr32.exe /s" wide ascii
                condition:
                    2 of them
            }

            rule CryptoMiner {
                meta:
                    description = "Detects cryptocurrency mining software"
                    severity = "high"
                    category = "malware"
                strings:
                    $a = "stratum" nocase
                    $b = "mining" nocase
                    $c = "hashrate" nocase
                    $d = "difficulty" nocase
                    $e = "blockchain" nocase
                    $f = "wallet" nocase
                    $g = "pool" nocase
                    $h = "nonce" nocase
                condition:
                    4 of them
            }

            rule macOSMalware {
                meta:
                    description = "Detects macOS-specific malware patterns"
                    severity = "high"
                    category = "malware"
                strings:
                    $a = "com.apple.security" wide ascii
                    $b = "NSWorkspace" wide ascii
                    $c = "NSRunningApplication" wide ascii
                    $d = "NSWorkspaceLaunchConfiguration" wide ascii
                    $e = "kLSSharedFileList" wide ascii
                    $f = "LSSharedFileList" wide ascii
                    $g = "NSWorkspaceLaunchDefault" wide ascii
                    $h = "NSWorkspaceLaunchNewInstance" wide ascii
                condition:
                    3 of them
            }
            """
            
            # Save basic rules to file
            rules_file = os.path.join(self.rules_path, 'basic_rules.yar')
            with open(rules_file, 'w') as f:
                f.write(basic_rules)
                
            # Compile rules
            self.rules = yara.compile(rules_file)
            logger.info("YARA rules compiled successfully")
            return True
            
        except yara.Error as e:
            logger.error(f"Error compiling YARA rules: {e}")
            self.rules = None
            return False
        except Exception as e:
            logger.error(f"Unexpected error initializing YARA rules: {e}")
            self.rules = None
            return False
            
    def add_rule(self, rule_name: str, rule_content: str) -> bool:
        """Add a new YARA rule."""
        try:
            rule_file = os.path.join(self.rules_path, f'{rule_name}.yar')
            with open(rule_file, 'w') as f:
                f.write(rule_content)
            
            # Recompile all rules
            rule_files = [os.path.join(self.rules_path, f) for f in os.listdir(self.rules_path) 
                         if f.endswith('.yar')]
            self.rules = yara.compile(filepaths={f: f for f in rule_files})
            logger.info(f"Added new YARA rule: {rule_name}")
            return True
        except Exception as e:
            logger.error(f"Error adding YARA rule: {e}")
            return False
            
    def scan_process(self, pid: int) -> Optional[Dict]:
        """Scan a specific process for malware patterns."""
        if not self.rules:
            logger.warning("YARA rules not initialized. Skipping scan.")
            return None
            
        try:
            proc = psutil.Process(pid)
            
            # Get process executable path
            exe_path = proc.exe()
            if not exe_path or not os.path.exists(exe_path):
                return None
                
            return self.scan_file(exe_path)
                
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.debug(f"Error accessing process {pid}: {e}")
        except Exception as e:
            logger.debug(f"Error scanning process {pid}: {e}")
            
        return None
        
    def scan_all_processes(self) -> List[Dict]:
        """Scan all running processes for malware patterns."""
        results = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                result = self.scan_process(proc.pid)
                if result:
                    results.append(result)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return results
        
    def scan_file(self, file_path: str) -> Optional[Dict]:
        """Scan a specific file for malware patterns."""
        if not self.rules:
            logger.warning("YARA rules not initialized. Skipping scan.")
            return None
            
        try:
            if not os.path.exists(file_path):
                return None
                
            # Skip certain file types and directories
            if any(skip in file_path.lower() for skip in [
                '.db', '.sqlite', '.json', '.txt', '.log', '.md',
                'workspacestorage', 'globalstorage', 'cache',
                'node_modules', '.git', '.vscode'
            ]):
                return None
                
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            
            # Check if we've already scanned this file
            if file_hash in self.scan_results:
                return self.scan_results[file_hash]
            
            # Scan the file
            matches = self.rules.match(file_path)
            
            if matches:
                result = {
                    'path': file_path,
                    'hash': file_hash,
                    'matches': [{
                        'rule': match.rule,
                        'meta': match.meta,
                        'strings': [{
                            'name': s[1],
                            'offset': s[0],
                            'matched': s[2].decode('utf-8', errors='ignore')
                        } for s in match.strings]
                    } for match in matches],
                    'timestamp': datetime.now().isoformat(),
                    'severity': max(match.meta.get('severity', 'low') for match in matches)
                }
                
                # Cache the result
                self.scan_results[file_hash] = result
                return result
                
        except yara.Error as e:
            logger.debug(f"YARA error scanning file {file_path}: {e}")
        except Exception as e:
            logger.debug(f"Error scanning file {file_path}: {e}")
            
        return None
        
    def scan_directory(self, directory: str, recursive: bool = True) -> List[Dict]:
        """Scan a directory for malware patterns."""
        if not self.rules:
            logger.warning("YARA rules not initialized. Skipping scan.")
            return []
            
        results = []
        
        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    try:
                        file_path = os.path.join(root, file)
                        result = self.scan_file(file_path)
                        if result:
                            results.append(result)
                    except Exception as e:
                        logger.debug(f"Error scanning file {file}: {e}")
                        
                if not recursive:
                    break
                    
        except Exception as e:
            logger.error(f"Error scanning directory {directory}: {e}")
            
        return results
        
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
        
    def get_scan_results(self) -> Dict[str, Dict]:
        """Get all cached scan results."""
        return self.scan_results
        
    def clear_scan_results(self):
        """Clear cached scan results."""
        self.scan_results.clear()
        
    def update_rules(self):
        """Update YARA rules from the rules directory."""
        try:
            rule_files = [os.path.join(self.rules_path, f) for f in os.listdir(self.rules_path) 
                         if f.endswith('.yar')]
            self.rules = yara.compile(filepaths={f: f for f in rule_files})
            logger.info("YARA rules updated successfully")
            return True
        except yara.Error as e:
            logger.error(f"Error updating YARA rules: {e}")
            return False

# Global instance
yara_scanner = YaraScanner() 