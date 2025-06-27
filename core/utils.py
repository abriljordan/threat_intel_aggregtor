import os
import requests

MITRE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
MITRE_LOCAL_PATH = "cache/mitre/enterprise-attack.json"

def download_mitre_attack_json(force_download=False):
    """
    Download the latest MITRE ATT&CK Enterprise STIX file if not present or if force_download is True.
    """
    os.makedirs(os.path.dirname(MITRE_LOCAL_PATH), exist_ok=True)
    if force_download or not os.path.exists(MITRE_LOCAL_PATH):
        print("Downloading latest MITRE ATT&CK data...")
        response = requests.get(MITRE_URL)
        response.raise_for_status()
        with open(MITRE_LOCAL_PATH, "wb") as f:
            f.write(response.content)
        print(f"Downloaded to {MITRE_LOCAL_PATH}")
    else:
        print("MITRE ATT&CK data already exists. Skipping download.")
