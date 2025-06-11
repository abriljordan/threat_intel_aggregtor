import os
from dotenv import load_dotenv

def load_env():
    load_dotenv()
    return {
        "ABUSEIPDB_API_KEY": os.getenv("ABUSEIPDB_API_KEY"),
        "VIRUSTOTAL_API_KEY": os.getenv("VIRUSTOTAL_API_KEY"),
        "SHODAN_API_KEY": os.getenv("SHODAN_API_KEY"),
    }