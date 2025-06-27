#!/usr/bin/env python3
"""
Test script to check the dashboard endpoint response.
"""

import requests
import json

def test_dashboard_response():
    """Test the dashboard endpoint response."""
    
    base_url = "http://localhost:5000"
    
    print("🔍 Testing dashboard endpoint response...")
    
    try:
        session = requests.Session()
        
        # Login first
        login_data = {
            'username': 'admin',
            'password': 'admin123'
        }
        
        print("1. Logging in...")
        login_response = session.post(f"{base_url}/auth/login", data=login_data, timeout=10)
        print(f"   Login status: {login_response.status_code}")
        
        if login_response.status_code not in [200, 302]:
            print(f"   Login failed: {login_response.text}")
            return
        
        print("   ✅ Login successful")
        
        # Test dashboard endpoint
        print("\n2. Testing dashboard endpoint...")
        dashboard_response = session.get(f"{base_url}/threat-intel/dashboard-data", timeout=10)
        print(f"   Dashboard status: {dashboard_response.status_code}")
        
        if dashboard_response.status_code == 200:
            try:
                data = dashboard_response.json()
                print("   ✅ Dashboard data received successfully")
                print(f"   Data keys: {list(data.keys())}")
                
                if 'charts' in data:
                    charts = data['charts']
                    print(f"   Charts available: {list(charts.keys())}")
                    
                    # Check each chart
                    for chart_name, chart_data in charts.items():
                        if chart_data:
                            print(f"   ✅ {chart_name}: Has data")
                            if isinstance(chart_data, dict):
                                if 'data' in chart_data and 'layout' in chart_data:
                                    print(f"      - Has data and layout")
                                else:
                                    print(f"      - Missing data/layout: {list(chart_data.keys())}")
                        else:
                            print(f"   ❌ {chart_name}: Empty or null")
                else:
                    print("   ❌ No 'charts' key in response")
                    print(f"   Response structure: {list(data.keys())}")
                
                # Save response to file for inspection
                with open('dashboard_response.json', 'w') as f:
                    json.dump(data, f, indent=2)
                print("\n   📄 Full response saved to 'dashboard_response.json'")
                
            except json.JSONDecodeError as e:
                print(f"   ❌ JSON decode error: {e}")
                print(f"   Response text: {dashboard_response.text[:500]}...")
        else:
            print(f"   ❌ Dashboard request failed: {dashboard_response.status_code}")
            print(f"   Response: {dashboard_response.text}")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    test_dashboard_response() 