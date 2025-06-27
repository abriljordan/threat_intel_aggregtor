#!/usr/bin/env python3
"""
Populate the threat intelligence database with real data for demo/showcase purposes.
"""

import requests
import json
import random
from threat_intelligence.threat_repository import ThreatIntelligenceRepository
from datetime import datetime
from mitreattack.stix20 import MitreAttackData
from core.utils import download_mitre_attack_json

# --- 1. MITRE ATT&CK Threat Actors & Malware Families ---
MITRE_GROUPS_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack-group.json"
MITRE_MALWARE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack-malware.json"

# --- 2. NVD CVE Feed (recent vulnerabilities) ---
# Start with the base endpoint. If this works, add parameters one by one.
NVD_RECENT_CVES_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# --- 3. Public Observables (sample IPs/domains/hashes) ---
ABUSEIPDB_RECENT_URL = "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90"
ABUSEIPDB_API_KEY = None  # Set your API key here if you want real IPs, else use sample

# --- 4. Helper: Random hash/domain generator for demo ---
def random_hash():
    return ''.join(random.choices('abcdef0123456789', k=64))

def random_domain():
    return f"malicious{random.randint(100,999)}.example.com"

# --- 5. Populate Threat Actors ---
def populate_threat_actors(repo):
    print("[+] Populating threat actors from MITRE ATT&CK...")
    try:
        r = requests.get(MITRE_GROUPS_URL, timeout=15)
        data = r.json()
        groups = [obj for obj in data.get('objects', []) if obj.get('type') == 'intrusion-set']
        for group in groups[:10]:  # Limit for demo
            actor_data = {
                'actor_id': group.get('external_references', [{}])[0].get('external_id', group.get('id')),
                'name': group.get('name'),
                'aliases': group.get('aliases', []),
                'description': group.get('description', ''),
                'country': group.get('country', ''),
                'motivation': group.get('primary_motivation', ''),
                'capabilities': [],
                'first_seen': group.get('first_seen', ''),
                'last_seen': group.get('last_seen', ''),
            }
            repo.store_threat_actor(actor_data)
        print(f"[+] Added {min(10, len(groups))} threat actors.")
    except Exception as e:
        print(f"[!] Error populating threat actors: {e}")

# --- 6. Populate Malware Families ---
def populate_malware_families(repo):
    print("[+] Populating malware families from MITRE ATT&CK...")
    try:
        r = requests.get(MITRE_MALWARE_URL, timeout=15)
        data = r.json()
        malware_list = [obj for obj in data.get('objects', []) if obj.get('type') == 'malware']
        for malware in malware_list[:10]:
            malware_data = {
                'malware_id': malware.get('external_references', [{}])[0].get('external_id', malware.get('id')),
                'name': malware.get('name'),
                'aliases': malware.get('aliases', []),
                'description': malware.get('description', ''),
                'family_type': malware.get('malware_types', [''])[0] if malware.get('malware_types') else '',
                'capabilities': [],
                'iocs': [],
                'behavior_patterns': [],
                'first_seen': malware.get('first_seen', ''),
                'last_seen': malware.get('last_seen', ''),
            }
            repo.store_malware_family(malware_data)
        print(f"[+] Added {min(10, len(malware_list))} malware families.")
    except Exception as e:
        print(f"[!] Error populating malware families: {e}")

# --- 7. Populate Vulnerabilities (CVEs) ---
NVD_API_KEY = "b32abeb2-b226-4b50-b6b2-e38900a2b95c"  # <-- Your NVD API Key
def populate_vulnerabilities(repo):
    print("[+] Populating vulnerabilities from NVD...")
    try:
        headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
        r = requests.get(NVD_RECENT_CVES_URL, headers=headers, timeout=15)
        if r.status_code != 200:
            print(f"[!] NVD API returned status code {r.status_code}. URL: {NVD_RECENT_CVES_URL}")
            print(f"[!] Response text: {r.text[:500]}")
            return
        cves = r.json().get('vulnerabilities', [])
        for cve in cves:
            cve_id = cve['cve']['id']
            descs = cve['cve'].get('descriptions', [])
            description = descs[0]['value'] if descs else ''
            metrics = cve['cve'].get('metrics', {})
            cvss = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
            vuln_data = {
                'cve_id': cve_id,
                'title': description[:80],
                'description': description,
                'severity': cvss.get('baseSeverity', 'N/A'),
                'cvss_score': cvss.get('baseScore', 0),
                'affected_products': '',
                'exploit_available': False,
                'patch_available': False,
            }
            repo.store_vulnerability(vuln_data)
        print(f"[+] Added {len(cves)} vulnerabilities.")
    except Exception as e:
        print(f"[!] Error populating vulnerabilities: {e}")

# --- 8. Populate Observables ---
def populate_observables(repo):
    print("[+] Populating observables (IPs/domains/hashes)...")
    # Use AbuseIPDB if API key is set, else use sample
    observables = []
    if ABUSEIPDB_API_KEY:
        try:
            headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
            r = requests.get(ABUSEIPDB_RECENT_URL, headers=headers, timeout=15)
            data = r.json()
            for entry in data.get('data', [])[:10]:
                observables.append({
                    'type': 'ip_address',
                    'value': entry['ipAddress'],
                    'confidence': 90,
                    'threat_score': 90,
                    'tags': json.dumps(['abuseipdb']),
                    'metadata': json.dumps({'country': entry.get('countryCode', '')}),
                })
        except Exception as e:
            print(f"[!] Error fetching AbuseIPDB: {e}")
    # Add sample domains and hashes
    for _ in range(5):
        observables.append({
            'type': 'domain',
            'value': random_domain(),
            'confidence': 80,
            'threat_score': 80,
            'tags': json.dumps(['malware']),
            'metadata': json.dumps({}),
        })
    for _ in range(5):
        observables.append({
            'type': 'hash',
            'value': random_hash(),
            'confidence': 70,
            'threat_score': 70,
            'tags': json.dumps(['malware']),
            'metadata': json.dumps({}),
        })
    for obs in observables:
        repo.store_observable(obs)
    print(f"[+] Added {len(observables)} observables.")

# --- 9. Populate Threat Actors and Malware Families using mitreattack-python ---
def populate_mitre_attack(repo):
    print("[+] Downloading and parsing MITRE ATT&CK data...")
    attack_data = MitreAttackData('cache/mitre/enterprise-attack.json')
    # Populate threat actors (intrusion sets)
    actors = attack_data.get_groups()
    for actor in actors[:10]:
        actor_data = {
            'actor_id': actor['id'],
            'name': actor['name'],
            'aliases': actor.get('aliases', []),
            'description': actor.get('description', ''),
            'country': actor.get('country', ''),
            'motivation': actor.get('primary_motivation', ''),
            'capabilities': [],
            'first_seen': actor.get('first_seen', ''),
            'last_seen': actor.get('last_seen', ''),
        }
        repo.store_threat_actor(actor_data)
    print(f"[+] Added {min(10, len(actors))} threat actors.")

    # Populate malware families
    malware_list = [s for s in attack_data.get_software() if s.get("type") == "malware"]
    for malware in malware_list[:10]:
        malware_data = {
            'malware_id': malware['id'],
            'name': malware['name'],
            'aliases': malware.get('aliases', []),
            'description': malware.get('description', ''),
            'family_type': malware.get('malware_types', [''])[0] if malware.get('malware_types') else '',
            'capabilities': [],
            'iocs': [],
            'behavior_patterns': [],
            'first_seen': malware.get('first_seen', ''),
            'last_seen': malware.get('last_seen', ''),
        }
        repo.store_malware_family(malware_data)
    print(f"[+] Added {min(10, len(malware_list))} malware families.")

# --- MAIN ---
def main():
    repo = ThreatIntelligenceRepository()
    repo.clear_all_data()  # Clear all data before repopulating for idempotency
    download_mitre_attack_json()  # Ensure latest MITRE ATT&CK data is downloaded
    populate_mitre_attack(repo)
    populate_vulnerabilities(repo)
    populate_observables(repo)
    print("[✓] Database population complete!")

if __name__ == "__main__":
    main() 