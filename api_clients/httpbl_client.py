import socket
import os
from dotenv import load_dotenv
from .base import BaseConnector

class HttpBLClient(BaseConnector):
    """Client for querying Project Honey Pot http:BL DNS-based blacklist."""
    def __init__(self, access_key=None):
        if not access_key:
            load_dotenv()
            access_key = os.getenv("HTTPBL_ACCESS_KEY")
        if not access_key:
            raise ValueError("No http:BL access key provided and HTTPBL_ACCESS_KEY not found in environment")
        self.access_key = access_key

    def check_ip(self, ip_address, **kwargs):
        reversed_ip = '.'.join(reversed(ip_address.split('.')))
        query = f'{self.access_key}.{reversed_ip}.dnsbl.httpbl.org'
        try:
            result = socket.gethostbyname(query)
            parts = result.split('.')
            if parts[0] != '127':
                return {'listed': False}
            days_since = int(parts[1])
            threat_score = int(parts[2])
            visitor_type = int(parts[3])
            types = []
            if visitor_type & 1:
                types.append('Suspicious')
            if visitor_type & 2:
                types.append('Harvester')
            if visitor_type & 4:
                types.append('Comment Spammer')
            if visitor_type == 0:
                types.append('Search Engine')
            return {
                'listed': True,
                'days_since': days_since,
                'threat_score': threat_score,
                'visitor_type': types
            }
        except Exception as e:
            return {'listed': False, 'error': str(e)} 