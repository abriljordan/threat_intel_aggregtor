
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
            