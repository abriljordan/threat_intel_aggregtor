import requests
import ipaddress
import hashlib
import re

class VirusTotalClient:
    """Client for interacting with the VirusTotal API"""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key):
        """Initialize the VirusTotal client with an API key"""
        if not api_key:
            raise ValueError("VirusTotal API key is required")
        self.api_key = api_key
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
    
    def _make_request(self, endpoint):
        """Make a GET request to the VirusTotal API"""
        try:
            response = requests.get(
                f"{self.BASE_URL}/{endpoint}",
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"VirusTotal API request failed: {str(e)}"}
    
    def _is_valid_ip(self, ip):
        """Check if a string is a valid IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _is_valid_domain(self, domain):
        """Check if a string is a valid domain name"""
        domain_regex = r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'
        return re.match(domain_regex, domain) is not None
    
    def _is_valid_hash(self, file_hash):
        """Check if a string is a valid MD5, SHA-1, or SHA-256 hash"""
        hash_lengths = {
            'md5': 32,
            'sha1': 40,
            'sha256': 64
        }
        
        file_hash = file_hash.lower()
        return any(
            len(file_hash) == length and all(c in '0123456789abcdef' for c in file_hash)
            for length in hash_lengths.values()
        )
    
    def check_ip(self, ip):
        """
        Check an IP address using VirusTotal
        
        Args:
            ip (str): IP address to check
            
        Returns:
            dict: Results from VirusTotal
        """
        if not self._is_valid_ip(ip):
            return {"error": f"Invalid IP address: {ip}"}
        
        result = self._make_request(f"ip_addresses/{ip}")
        if "error" in result:
            return result
            
        return self._format_ip_response(result)
    
    def check_domain(self, domain):
        """
        Check a domain using VirusTotal
        
        Args:
            domain (str): Domain to check
            
        Returns:
            dict: Results from VirusTotal
        """
        if not self._is_valid_domain(domain):
            return {"error": f"Invalid domain: {domain}"}
        
        result = self._make_request(f"domains/{domain}")
        if "error" in result:
            return result
            
        return self._format_domain_response(result)
    
    def check_hash(self, file_hash):
        """
        Check a file hash using VirusTotal
        
        Args:
            file_hash (str): File hash (MD5, SHA-1, or SHA-256)
            
        Returns:
            dict: Results from VirusTotal
        """
        if not self._is_valid_hash(file_hash):
            return {"error": "Invalid file hash. Must be MD5, SHA-1, or SHA-256"}
        
        result = self._make_request(f"files/{file_hash}")
        if "error" in result:
            return result
            
        return self._format_hash_response(result)
    
    def _format_ip_response(self, data):
        """Format the IP address response"""
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        return {
            "success": True,
            "data": {
                "id": data.get('data', {}).get('id', ''),
                "type": "ip_address",
                "attributes": {
                    "asn": attributes.get('asn', ''),
                    "as_owner": attributes.get('as_owner', ''),
                    "country": attributes.get('country', ''),
                    "last_analysis_stats": stats,
                    "last_analysis_results": attributes.get('last_analysis_results', {})
                }
            }
        }
    
    def _format_domain_response(self, data):
        """Format the domain response"""
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        return {
            "success": True,
            "data": {
                "id": data.get('data', {}).get('id', ''),
                "type": "domain",
                "attributes": {
                    "last_dns_records": attributes.get('last_dns_records', []),
                    "last_analysis_stats": stats,
                    "last_analysis_results": attributes.get('last_analysis_results', {}),
                    "categories": attributes.get('categories', {})
                }
            }
        }
    
    def _format_hash_response(self, data):
        """Format the file hash response"""
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        return {
            "success": True,
            "data": {
                "id": data.get('data', {}).get('id', ''),
                "type": "file",
                "attributes": {
                    "meaningful_name": attributes.get('meaningful_name', ''),
                    "type_description": attributes.get('type_description', ''),
                    "size": attributes.get('size', 0),
                    "last_analysis_stats": stats,
                    "last_analysis_results": attributes.get('last_analysis_results', {})
                }
            }
        }

# Example usage
if __name__ == "__main__":
    import os
    from dotenv import load_dotenv
    
    load_dotenv()
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    
    if not api_key:
        print("Error: VIRUSTOTAL_API_KEY not found in .env file")
    else:
        client = VirusTotalClient(api_key)
        
        # Example IP lookup
        print("Testing IP lookup...")
        result = client.check_ip("8.8.8.8")
        print("IP Lookup Result:", result.get('data', {}).get('id', 'N/A'))
        
        # Example domain lookup
        print("\nTesting domain lookup...")
        result = client.check_domain("google.com")
        print("Domain Lookup Result:", result.get('data', {}).get('id', 'N/A'))
        
        # Example hash lookup (using a known test hash)
        test_hash = "44d88612fea8a8f36de82e1278abb02f"  # Example MD5 hash
        print(f"\nTesting hash lookup for {test_hash}...")
        result = client.check_hash(test_hash)
        print("Hash Lookup Result:", result.get('data', {}).get('id', 'N/A'))