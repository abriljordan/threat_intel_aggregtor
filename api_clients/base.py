class BaseConnector:
    """Base class for all threat intelligence API connectors."""
    
    def check_ip(self, ip_address, **kwargs):
        """Check an IP address. Should be implemented by subclasses."""
        raise NotImplementedError("check_ip must be implemented by the connector.")

    def check_domain(self, domain, **kwargs):
        """Check a domain. Should be implemented by subclasses if supported."""
        raise NotImplementedError("check_domain must be implemented by the connector.")

    def check_hash(self, file_hash, **kwargs):
        """Check a file hash. Should be implemented by subclasses if supported."""
        raise NotImplementedError("check_hash must be implemented by the connector.") 