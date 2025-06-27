#!/usr/bin/env python3
"""
Test script to verify dashboard access and data retrieval.
"""

import requests
import json

def test_dashboard_endpoints():
    """Test both dashboard endpoints."""
    
    base_url = "http://localhost:5000"
    
    print("🔍 Testing dashboard endpoints...")
    
    # Test 1: Test dashboard (no auth required)
    print("\n1. Testing test dashboard endpoint (no auth required)...")
    try:
        response = requests.get(f"{base_url}/threat-intel/test-dashboard-data", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Test dashboard accessible - Status: {response.status_code}")
            print(f"   Charts available: {list(data.get('charts', {}).keys())}")
        else:
            print(f"❌ Test dashboard failed - Status: {response.status_code}")
            print(f"   Response: {response.text}")
    except Exception as e:
        print(f"❌ Test dashboard error: {e}")
    
    # Test 2: Real dashboard (auth required)
    print("\n2. Testing real dashboard endpoint (auth required)...")
    try:
        response = requests.get(f"{base_url}/threat-intel/dashboard-data", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Real dashboard accessible - Status: {response.status_code}")
            print(f"   Charts available: {list(data.get('charts', {}).keys())}")
        elif response.status_code == 401 or response.status_code == 302:
            print(f"⚠️  Real dashboard requires authentication - Status: {response.status_code}")
            print("   This is expected behavior - you need to log in first")
        else:
            print(f"❌ Real dashboard failed - Status: {response.status_code}")
            print(f"   Response: {response.text}")
    except Exception as e:
        print(f"❌ Real dashboard error: {e}")
    
    # Test 3: Try to access with session
    print("\n3. Testing login and dashboard access...")
    try:
        session = requests.Session()
        
        # First, try to login
        login_data = {
            'username': 'admin',
            'password': 'admin123'
        }
        
        login_response = session.post(f"{base_url}/auth/login", data=login_data, timeout=10)
        print(f"   Login response status: {login_response.status_code}")
        
        if login_response.status_code in [200, 302]:
            print("   ✅ Login successful")
            
            # Now try to access the real dashboard
            dashboard_response = session.get(f"{base_url}/threat-intel/dashboard-data", timeout=10)
            if dashboard_response.status_code == 200:
                data = dashboard_response.json()
                print(f"   ✅ Real dashboard accessible after login - Status: {dashboard_response.status_code}")
                print(f"   Charts available: {list(data.get('charts', {}).keys())}")
            else:
                print(f"   ❌ Real dashboard still failed - Status: {dashboard_response.status_code}")
                print(f"   Response: {dashboard_response.text}")
        else:
            print(f"   ❌ Login failed - Status: {login_response.status_code}")
            print(f"   Response: {login_response.text}")
            
    except Exception as e:
        print(f"❌ Login/dashboard test error: {e}")

def test_app_running():
    """Test if the app is running."""
    print("🔍 Testing if app is running...")
    
    try:
        response = requests.get("http://localhost:5000", timeout=5)
        if response.status_code in [200, 302]:
            print("✅ App is running on localhost:5000")
            return True
        else:
            print(f"❌ App responded with status: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ App is not running on localhost:5000")
        print("   Please start the app with: python run.py")
        return False
    except Exception as e:
        print(f"❌ Error testing app: {e}")
        return False

if __name__ == '__main__':
    if test_app_running():
        test_dashboard_endpoints()
    else:
        print("\n💡 To start the app, run: python run.py") 