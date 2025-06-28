#!/usr/bin/env python3
"""
Test script to check if API clients are working properly.
"""

import os
from dotenv import load_dotenv
from api_clients.abuseipdb_client import AbuseIPDBClient
from api_clients.virustotal_client import VirusTotalClient
from api_clients.shodan_client import ShodanClient
from api_clients.httpbl_client import HttpBLClient

def test_api_clients():
    """Test all API clients with the configured API keys."""
    
    # Load environment variables
    load_dotenv()
    
    print("🔍 Testing API Clients...")
    print("=" * 50)
    
    # Test AbuseIPDB
    print("\n1. Testing AbuseIPDB Client:")
    abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')
    print(f"   API Key found: {'Yes' if abuseipdb_key else 'No'}")
    if abuseipdb_key:
        print(f"   API Key: {abuseipdb_key[:10]}...{abuseipdb_key[-10:]}")
        try:
            client = AbuseIPDBClient(abuseipdb_key)
            result = client.check_ip('47.128.27.190')
            print(f"   ✅ AbuseIPDB test successful!")
            print(f"   Result: {result}")
        except Exception as e:
            print(f"   ❌ AbuseIPDB test failed: {e}")
    else:
        print("   ❌ No AbuseIPDB API key found")
    
    # Test VirusTotal
    print("\n2. Testing VirusTotal Client:")
    virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
    print(f"   API Key found: {'Yes' if virustotal_key else 'No'}")
    if virustotal_key:
        print(f"   API Key: {virustotal_key[:10]}...{virustotal_key[-10:]}")
        try:
            client = VirusTotalClient(virustotal_key)
            result = client.check_ip('47.128.27.190')
            print(f"   ✅ VirusTotal test successful!")
            print(f"   Result: {result}")
        except Exception as e:
            print(f"   ❌ VirusTotal test failed: {e}")
    else:
        print("   ❌ No VirusTotal API key found")
    
    # Test Shodan
    print("\n3. Testing Shodan Client:")
    shodan_key = os.getenv('SHODAN_API_KEY')
    print(f"   API Key found: {'Yes' if shodan_key else 'No'}")
    if shodan_key:
        print(f"   API Key: {shodan_key[:10]}...{shodan_key[-10:]}")
        try:
            client = ShodanClient(shodan_key)
            result = client.check_ip('47.128.27.190')
            print(f"   ✅ Shodan test successful!")
            print(f"   Result: {result}")
        except Exception as e:
            print(f"   ❌ Shodan test failed: {e}")
    else:
        print("   ❌ No Shodan API key found")
    
    # Test HttpBL
    print("\n4. Testing HttpBL Client:")
    httpbl_key = os.getenv('HTTPBL_ACCESS_KEY')
    print(f"   API Key found: {'Yes' if httpbl_key else 'No'}")
    if httpbl_key:
        print(f"   API Key: {httpbl_key[:10]}...{httpbl_key[-10:]}")
        try:
            client = HttpBLClient(httpbl_key)
            result = client.check_ip('47.128.27.190')
            print(f"   ✅ HttpBL test successful!")
            print(f"   Result: {result}")
        except Exception as e:
            print(f"   ❌ HttpBL test failed: {e}")
    else:
        print("   ❌ No HttpBL API key found")
    
    print("\n" + "=" * 50)
    print("🏁 API Client Testing Complete!")

if __name__ == "__main__":
    test_api_clients() 