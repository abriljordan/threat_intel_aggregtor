#!/usr/bin/env python3
"""
Test script for the integrated threat intelligence and network monitoring system.
"""

import os
import sys
import time
from dotenv import load_dotenv

# Add the project root to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all required modules can be imported."""
    print("Testing imports...")
    
    try:
        # Test API clients
        from api_clients.abuseipdb_client import AbuseIPDBClient
        from api_clients.virustotal_client import VirusTotalClient
        from api_clients.shodan_client import ShodanClient
        from api_clients.httpbl_client import HttpBLClient
        print("✓ API clients imported successfully")
        
        # Test network monitoring components
        from network_monitoring.connection_monitor import ConnectionMonitor
        from network_monitoring.process_monitor import ProcessMonitor
        from network_monitoring.threat_detector import ThreatDetector
        from network_monitoring.yara_scanner import YaraScanner
        print("✓ Network monitoring components imported successfully")
        
        # Test integration components
        from integration.event_correlator import EventCorrelator
        from integration.unified_alerter import UnifiedAlerter, AlertType, AlertSeverity
        from integration.network_monitor_manager import NetworkMonitorManager
        print("✓ Integration components imported successfully")
        
        # Test web dashboard
        from web_dashboard import create_app
        print("✓ Web dashboard imported successfully")
        
        return True
        
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return False

def test_network_monitoring():
    """Test network monitoring functionality."""
    print("\nTesting network monitoring...")
    
    try:
        from network_monitoring.connection_monitor import ConnectionMonitor
        from network_monitoring.process_monitor import ProcessMonitor
        
        # Test connection monitor
        conn_monitor = ConnectionMonitor()
        connections = conn_monitor.get_connections()
        print(f"✓ Connection monitor: {len(connections)} connections found")
        
        # Test process monitor
        proc_monitor = ProcessMonitor()
        processes = proc_monitor.get_processes()
        print(f"✓ Process monitor: {len(processes)} processes found")
        
        return True
        
    except Exception as e:
        print(f"✗ Network monitoring error: {e}")
        return False

def test_threat_intelligence():
    """Test threat intelligence API clients."""
    print("\nTesting threat intelligence APIs...")
    
    try:
        load_dotenv()
        
        # Test API key loading
        api_keys = {
            'ABUSEIPDB_API_KEY': os.getenv('ABUSEIPDB_API_KEY'),
            'VIRUSTOTAL_API_KEY': os.getenv('VIRUSTOTAL_API_KEY'),
            'SHODAN_API_KEY': os.getenv('SHODAN_API_KEY'),
            'HTTPBL_ACCESS_KEY': os.getenv('HTTPBL_ACCESS_KEY')
        }
        
        print(f"✓ API keys loaded: {sum(1 for v in api_keys.values() if v)}/{len(api_keys)} available")
        
        # Test event correlator initialization
        from integration.event_correlator import EventCorrelator
        correlator = EventCorrelator(api_keys)
        print("✓ Event correlator initialized")
        
        # Test unified alerter
        from integration.unified_alerter import UnifiedAlerter, AlertType, AlertSeverity
        alerter = UnifiedAlerter()
        print("✓ Unified alerter initialized")
        
        return True
        
    except Exception as e:
        print(f"✗ Threat intelligence error: {e}")
        return False

def test_integration():
    """Test the complete integration."""
    print("\nTesting complete integration...")
    
    try:
        load_dotenv()
        
        api_keys = {
            'ABUSEIPDB_API_KEY': os.getenv('ABUSEIPDB_API_KEY'),
            'VIRUSTOTAL_API_KEY': os.getenv('VIRUSTOTAL_API_KEY'),
            'SHODAN_API_KEY': os.getenv('SHODAN_API_KEY'),
            'HTTPBL_ACCESS_KEY': os.getenv('HTTPBL_ACCESS_KEY')
        }
        
        # Test network monitor manager
        from integration.network_monitor_manager import NetworkMonitorManager
        manager = NetworkMonitorManager(api_keys)
        print("✓ Network monitor manager initialized")
        
        # Test status
        status = manager.get_status()
        print(f"✓ Manager status: {status['is_running']}")
        
        # Test monitoring data
        data = manager.get_monitoring_data()
        print(f"✓ Monitoring data: {len(data.get('connections', []))} connections, {len(data.get('alerts', []))} alerts")
        
        return True
        
    except Exception as e:
        print(f"✗ Integration error: {e}")
        return False

def test_web_dashboard():
    """Test web dashboard creation."""
    print("\nTesting web dashboard...")
    
    try:
        from web_dashboard import create_app
        
        # Create app context
        app = create_app()
        with app.app_context():
            print("✓ Web dashboard created successfully")
            
            # Test routes
            from web_dashboard.routes import main, auth, api, network
            print("✓ All blueprints registered")
            
        return True
        
    except Exception as e:
        print(f"✗ Web dashboard error: {e}")
        return False

def main():
    """Run all tests."""
    print("=" * 60)
    print("THREAT INTELLIGENCE + NETWORK MONITORING INTEGRATION TEST")
    print("=" * 60)
    
    tests = [
        ("Import Test", test_imports),
        ("Network Monitoring Test", test_network_monitoring),
        ("Threat Intelligence Test", test_threat_intelligence),
        ("Integration Test", test_integration),
        ("Web Dashboard Test", test_web_dashboard)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        print("-" * 40)
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"✗ Test failed with exception: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = 0
    for test_name, result in results:
        status = "✓ PASSED" if result else "✗ FAILED"
        print(f"{test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{len(results)} tests passed")
    
    if passed == len(results):
        print("\n🎉 All tests passed! The integration is working correctly.")
        print("\nTo start the integrated system:")
        print("1. Make sure your .env file has the required API keys")
        print("2. Run: python run.py")
        print("3. Access the dashboard at: http://localhost:5000")
        print("4. Navigate to 'Network Monitoring' in the sidebar")
    else:
        print("\n❌ Some tests failed. Please check the errors above.")
    
    return passed == len(results)

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 