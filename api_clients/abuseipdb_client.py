import os
import requests
from dotenv import load_dotenv

class AbuseIPDBClient:
    """Client for interacting with the AbuseIPDB API."""
    
    def __init__(self, api_key=None):
        """Initialize the AbuseIPDB client with an API key.
        
        Args:
            api_key (str, optional): Your AbuseIPDB API key. If not provided,
                                 it will be loaded from the .env file.
        """
        if not api_key:
            load_dotenv()
            api_key = os.getenv("ABUSEIPDB_API_KEY")
            
        if not api_key:
            raise ValueError("No API key provided and ABUSEIPDB_API_KEY not found in environment")
            
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
    
    def check_ip(self, ip_address, max_age_in_days=90):
        """Check an IP address against the AbuseIPDB database.
        
        Args:
            ip_address (str): The IP address to check
            max_age_in_days (int, optional): Maximum age of reports to return (1-365). Defaults to 90.
            
        Returns:
            dict: A dictionary containing the IP check results
        """
        if not ip_address:
            raise ValueError("IP address cannot be empty")
            
        url = f"{self.base_url}/check"
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": min(max(1, max_age_in_days), 365)  # Ensure value is between 1-365
        }
        
        try:
            print(f"Making request to AbuseIPDB API for IP: {ip_address}")  # Debug print
            response = requests.get(url, headers=self.headers, params=params, timeout=10)
            
            # Print response details for debugging
            print(f"Response status code: {response.status_code}")
            print(f"Response headers: {response.headers}")
            
            response.raise_for_status()
            
            data = response.json()
            print(f"Response data: {data}")  # Debug print
            
            if "data" not in data:
                return {"error": f"Invalid response format from AbuseIPDB API: {data}"}
                
            return {"data": data["data"]}
            
        except requests.exceptions.RequestException as e:
            error_msg = f"API request failed: {str(e)}"
            if hasattr(e.response, 'text'):
                error_msg += f"\nResponse: {e.response.text}"
            return {"error": error_msg}
        except (ValueError, KeyError) as e:
            return {"error": f"Error processing API response: {str(e)}"}


def main():
    """Command-line interface for testing the AbuseIPDB client."""
    import argparse
    from pprint import pprint
    
    # Load API key from environment
    load_dotenv()
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    
    if not api_key:
        print("Error: ABUSEIPDB_API_KEY not found in environment")
        return
    
    print(f"Using API key: {api_key[:4]}...{api_key[-4:]}")  # Show first/last 4 chars
    
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Check an IP address using AbuseIPDB")
    parser.add_argument("ip", help="IP address to check")
    parser.add_argument("--days", type=int, default=90, 
                      help="Maximum age of reports in days (1-365)")
    args = parser.parse_args()
    
    # Create client and make request
    client = AbuseIPDBClient(api_key)
    result = client.check_ip(args.ip, args.days)
    
    # Display results
    if "error" in result:
        print(f"Error: {result['error']}")
    else:
        print("\n=== AbuseIPDB Report ===")
        pprint(result["data"])


if __name__ == "__main__":
    main()
