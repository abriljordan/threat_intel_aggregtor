import shodan
import ipaddress
from .base import BaseConnector

class ShodanClient(BaseConnector):
    """Client for interacting with the Shodan API"""
    
    def __init__(self, api_key):
        """Initialize the Shodan client with an API key"""
        if not api_key:
            raise ValueError("Shodan API key is required")
        self.api = shodan.Shodan(api_key)
    
    def check_ip(self, ip_address):
        """
        Check an IP address using Shodan
        
        Args:
            ip_address (str): IP address to check
            
        Returns:
            dict: Results from Shodan
        """
        try:
            # Validate IP address
            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                return {"error": f"Invalid IP address: {ip_address}"}
                
            # Make the API call
            host = self.api.host(ip_address)
            
            # Format the response
            return {
                "success": True,
                "data": {
                    "ip_str": host.get('ip_str', ''),
                    "country_name": host.get('country_name', 'Unknown'),
                    "city": host.get('city', 'Unknown'),
                    "org": host.get('org', 'Unknown'),
                    "os": host.get('os', 'Unknown'),
                    "ports": host.get('ports', []),
                    "hostnames": host.get('hostnames', []),
                    "vulns": host.get('vulns', []),
                    "data": host.get('data', [])
                }
            }
            
        except shodan.APIError as e:
            return {"error": f"Shodan API error: {str(e)}"}
        except Exception as e:
            return {"error": f"Error checking IP with Shodan: {str(e)}"}
    
    def check_domain(self, domain):
        """
        Search for information about a domain
        
        Args:
            domain (str): Domain to search for
            
        Returns:
            dict: Results from Shodan
        """
        try:
            # Make the API call
            results = self.api.search(f"hostname:{domain}")
            
            # Format the response
            formatted_results = []
            for result in results['matches']:
                formatted_results.append({
                    'ip': result.get('ip_str', ''),
                    'port': result.get('port', ''),
                    'transport': result.get('transport', 'tcp'),
                    'product': result.get('product', ''),
                    'version': result.get('version', ''),
                    'os': result.get('os', ''),
                    'org': result.get('org', ''),
                    'isp': result.get('isp', ''),
                    'hostnames': result.get('hostnames', []),
                })
            
            return {
                "success": True,
                "data": {
                    "total": results.get('total', 0),
                    "results": formatted_results
                }
            }
            
        except shodan.APIError as e:
            return {"error": f"Shodan API error: {str(e)}"}
        except Exception as e:
            return {"error": f"Error searching domain with Shodan: {str(e)}"}

# Example usage
if __name__ == "__main__":
    import os
    from dotenv import load_dotenv
    
    load_dotenv()
    api_key = os.getenv("SHODAN_API_KEY")
    
    if not api_key:
        print("Error: SHODAN_API_KEY not found in .env file")
    else:
        client = ShodanClient(api_key)
        
        # Example IP lookup
        print("Testing IP lookup...")
        result = client.check_ip("8.8.8.8")
        print("IP Lookup Result:", result)
        
        # Example domain search
        print("\nTesting domain search...")
        result = client.check_domain("google.com")
        print(f"Domain Search Results ({result.get('data', {}).get('total', 0)} found):")
        for i, r in enumerate(result.get('data', {}).get('results', [])[:3], 1):
            print(f"{i}. {r['ip']}:{r['port']} - {r.get('product', 'Unknown')}")