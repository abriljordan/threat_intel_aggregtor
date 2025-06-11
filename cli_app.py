import argparse
import json
from typing import Dict, Any
import sys

def format_abuseipdb(data: Dict[str, Any]) -> str:
    """Format AbuseIPDB results"""
    if "error" in data:
        return f"Error: {data['error']}"
        
    # Extract the actual data from the nested structure
    ip_data = data.get("data", {})
    
    result = []
    result.append("=== AbuseIPDB Report ===")
    result.append(f"IP Address: {ip_data.get('ipAddress', 'N/A')}")
    result.append(f"Country: {ip_data.get('countryCode', 'N/A')}")
    result.append(f"ISP: {ip_data.get('isp', 'N/A')}")
    result.append(f"Abuse Confidence: {ip_data.get('abuseConfidenceScore', 0)}%")
    result.append(f"Total Reports: {ip_data.get('totalReports', 0)}")
    result.append(f"Last Reported: {ip_data.get('lastReportedAt', 'N/A')}")
    result.append(f"Usage Type: {ip_data.get('usageType', 'N/A')}")
    result.append(f"Domain: {ip_data.get('domain', 'N/A')}")
    if ip_data.get('hostnames'):
        result.append(f"Hostnames: {', '.join(ip_data['hostnames'])}")
    return "\n".join(result)

def format_virustotal(data: Dict[str, Any]) -> str:
    """Format VirusTotal results"""
    if "error" in data:
        return f"Error: {data['error']}"
        
    # Extract the actual data from the nested structure
    vt_data = data.get("data", {})
    attributes = vt_data.get("attributes", {})
    
    result = []
    result.append("=== VirusTotal Report ===")
    result.append(f"ID: {vt_data.get('id', 'N/A')}")
    result.append(f"Type: {vt_data.get('type', 'N/A')}")
    
    # Add ASN information if available
    if attributes.get('asn'):
        result.append(f"\nNetwork Information:")
        result.append(f"ASN: {attributes.get('asn', 'N/A')}")
        result.append(f"AS Owner: {attributes.get('as_owner', 'N/A')}")
        result.append(f"Country: {attributes.get('country', 'N/A')}")
    
    # Add detection statistics
    if 'last_analysis_stats' in attributes:
        result.append("\nDetection Statistics:")
        stats = attributes['last_analysis_stats']
        result.append(f"Malicious: {stats.get('malicious', 0)}")
        result.append(f"Suspicious: {stats.get('suspicious', 0)}")
        result.append(f"Undetected: {stats.get('undetected', 0)}")
        result.append(f"Timeout: {stats.get('timeout', 0)}")
        result.append(f"Total: {sum(stats.values())}")
    
    return "\n".join(result)

def format_shodan(data: Dict[str, Any]) -> str:
    """Format Shodan results"""
    if "error" in data:
        return f"Error: {data['error']}"
        
    # Extract the actual data from the nested structure
    shodan_data = data.get("data", {})
    
    result = []
    result.append("=== Shodan Report ===")
    result.append(f"IP: {shodan_data.get('ip_str', 'N/A')}")
    result.append(f"Organization: {shodan_data.get('org', 'N/A')}")
    result.append(f"Operating System: {shodan_data.get('os', 'N/A')}")
    result.append(f"Country: {shodan_data.get('country_name', 'N/A')}")
    result.append(f"City: {shodan_data.get('city', 'N/A')}")
    
    # Add hostnames if available
    if shodan_data.get('hostnames'):
        result.append(f"\nHostnames:")
        for hostname in shodan_data['hostnames']:
            result.append(f"- {hostname}")
    
    # Add open ports if available
    if shodan_data.get('ports'):
        result.append(f"\nOpen Ports: {', '.join(map(str, shodan_data['ports']))}")
    
    # Add vulnerabilities if available
    if shodan_data.get('vulns'):
        result.append(f"\nVulnerabilities:")
        for vuln in shodan_data['vulns']:
            result.append(f"- {vuln}")
    
    return "\n".join(result)

def main():
    parser = argparse.ArgumentParser(description='Threat Intelligence Aggregator CLI')
    parser.add_argument('--api', choices=['abuseipdb', 'virustotal', 'shodan'], 
                      required=True, help='API to query')
    parser.add_argument('--query', required=True, help='IP address or domain to query')
    parser.add_argument('--format', choices=['text', 'json'], default='text',
                      help='Output format (default: text)')
    
    args = parser.parse_args()
    
    try:
        # Import API clients here to avoid circular imports
        from api_clients.abuseipdb_client import AbuseIPDBClient
        from api_clients.virustotal_client import VirusTotalClient
        from api_clients.shodan_client import ShodanClient
        from core.env_loader import load_env
        
        # Load environment variables
        env = load_env()
        
        # Initialize appropriate client
        if args.api == 'abuseipdb':
            client = AbuseIPDBClient(env.get("ABUSEIPDB_API_KEY"))
            result = client.check_ip(args.query)
            formatter = format_abuseipdb
        elif args.api == 'virustotal':
            client = VirusTotalClient(env.get("VIRUSTOTAL_API_KEY"))
            result = client.check_ip(args.query)
            formatter = format_virustotal
        elif args.api == 'shodan':
            client = ShodanClient(env.get("SHODAN_API_KEY"))
            result = client.check_ip(args.query)
            formatter = format_shodan
            
        # Output results
        if args.format == 'json':
            print(json.dumps(result, indent=2))
        else:
            print(formatter(result))
            
    except KeyError as e:
        print(f"Error: Missing API key in .env file: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main() 