"""
Cache Configuration and Management

This module provides centralized cache configuration and management
for the threat intelligence aggregator.
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import threading
import time

logger = logging.getLogger(__name__)

class CacheConfig:
    """Centralized cache configuration and management."""
    
    # Cache TTL settings (in seconds)
    TTL_SETTINGS = {
        'api_responses': 300,        # 5 minutes for API calls
        'mitre_data': 86400,         # 24 hours for MITRE data
        'rss_feeds': 600,            # 10 minutes for RSS feeds
        'correlation_results': 300,  # 5 minutes for correlation
        'session_data': 3600,        # 1 hour for session data
        'threat_reports': 1800,      # 30 minutes for report cache
        'security_news': 300,        # 5 minutes for news
    }
    
    # Cache storage types
    STORAGE_TYPES = {
        'file': 'file_based',
        'memory': 'in_memory',
        'database': 'database',
        'redis': 'redis'  # Future enhancement
    }
    
    def __init__(self, cache_dir: str = "cache"):
        """Initialize cache configuration."""
        self.cache_dir = cache_dir
        self.cache_locks = {}
        self._setup_cache_directories()
    
    def _setup_cache_directories(self):
        """Create cache directories if they don't exist."""
        directories = [
            self.cache_dir,
            f"{self.cache_dir}/mitre",
            f"{self.cache_dir}/api",
            f"{self.cache_dir}/rss",
            f"{self.cache_dir}/correlation",
            f"{self.cache_dir}/reports"
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    def get_cache_path(self, cache_type: str, key: str) -> str:
        """Get cache file path for a given type and key."""
        return os.path.join(self.cache_dir, cache_type, f"{key}.json")
    
    def get_ttl(self, cache_type: str) -> int:
        """Get TTL for a cache type."""
        return self.TTL_SETTINGS.get(cache_type, 300)
    
    def is_cache_valid(self, cache_path: str, ttl: int) -> bool:
        """Check if cache file is still valid."""
        try:
            if not os.path.exists(cache_path):
                return False
            
            file_time = os.path.getmtime(cache_path)
            age = time.time() - file_time
            return age < ttl
            
        except Exception as e:
            logger.error(f"Error checking cache validity: {e}")
            return False
    
    def save_to_cache(self, cache_path: str, data: Any) -> bool:
        """Save data to cache file."""
        try:
            cache_data = {
                'data': data,
                'timestamp': datetime.now().isoformat(),
                'created_at': time.time()
            }
            
            with open(cache_path, 'w') as f:
                json.dump(cache_data, f, indent=2)
            
            return True
            
        except Exception as e:
            logger.error(f"Error saving to cache: {e}")
            return False
    
    def load_from_cache(self, cache_path: str) -> Optional[Any]:
        """Load data from cache file."""
        try:
            if not os.path.exists(cache_path):
                return None
            
            with open(cache_path, 'r') as f:
                cache_data = json.load(f)
            
            return cache_data.get('data')
            
        except Exception as e:
            logger.error(f"Error loading from cache: {e}")
            return None
    
    def clear_cache(self, cache_type: str = None, key: str = None):
        """Clear cache for specific type or key."""
        try:
            if cache_type and key:
                # Clear specific cache file
                cache_path = self.get_cache_path(cache_type, key)
                if os.path.exists(cache_path):
                    os.remove(cache_path)
                    logger.info(f"Cleared cache: {cache_path}")
            
            elif cache_type:
                # Clear all cache files of a type
                cache_dir = os.path.join(self.cache_dir, cache_type)
                if os.path.exists(cache_dir):
                    for file in os.listdir(cache_dir):
                        if file.endswith('.json'):
                            os.remove(os.path.join(cache_dir, file))
                    logger.info(f"Cleared all {cache_type} cache files")
            
            else:
                # Clear all cache
                for cache_type_dir in os.listdir(self.cache_dir):
                    cache_type_path = os.path.join(self.cache_dir, cache_type_dir)
                    if os.path.isdir(cache_type_path):
                        for file in os.listdir(cache_type_path):
                            if file.endswith('.json'):
                                os.remove(os.path.join(cache_type_path, file))
                logger.info("Cleared all cache files")
                
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        stats = {
            'total_size': 0,
            'file_count': 0,
            'cache_types': {}
        }
        
        try:
            for cache_type in os.listdir(self.cache_dir):
                cache_type_path = os.path.join(self.cache_dir, cache_type)
                if os.path.isdir(cache_type_path):
                    type_stats = {
                        'files': 0,
                        'size': 0,
                        'oldest': None,
                        'newest': None
                    }
                    
                    for file in os.listdir(cache_type_path):
                        if file.endswith('.json'):
                            file_path = os.path.join(cache_type_path, file)
                            file_size = os.path.getsize(file_path)
                            file_time = os.path.getmtime(file_path)
                            
                            type_stats['files'] += 1
                            type_stats['size'] += file_size
                            
                            if type_stats['oldest'] is None or file_time < type_stats['oldest']:
                                type_stats['oldest'] = file_time
                            if type_stats['newest'] is None or file_time > type_stats['newest']:
                                type_stats['newest'] = file_time
                    
                    stats['cache_types'][cache_type] = type_stats
                    stats['total_size'] += type_stats['size']
                    stats['file_count'] += type_stats['files']
            
            # Convert timestamps to readable format
            for cache_type, type_stats in stats['cache_types'].items():
                if type_stats['oldest']:
                    type_stats['oldest'] = datetime.fromtimestamp(type_stats['oldest']).isoformat()
                if type_stats['newest']:
                    type_stats['newest'] = datetime.fromtimestamp(type_stats['newest']).isoformat()
            
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
        
        return stats
    
    def cleanup_expired_cache(self):
        """Remove expired cache files."""
        try:
            for cache_type in os.listdir(self.cache_dir):
                cache_type_path = os.path.join(self.cache_dir, cache_type)
                if os.path.isdir(cache_type_path):
                    ttl = self.get_ttl(cache_type)
                    
                    for file in os.listdir(cache_type_path):
                        if file.endswith('.json'):
                            file_path = os.path.join(cache_type_path, file)
                            if not self.is_cache_valid(file_path, ttl):
                                os.remove(file_path)
                                logger.info(f"Removed expired cache: {file_path}")
                                
        except Exception as e:
            logger.error(f"Error cleaning up expired cache: {e}")

# Global cache configuration instance
cache_config = CacheConfig()

# Cache decorator for easy use
def cached(cache_type: str, key_func=None):
    """Decorator for caching function results."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = f"{func.__name__}_{hash(str(args) + str(kwargs))}"
            
            cache_path = cache_config.get_cache_path(cache_type, cache_key)
            ttl = cache_config.get_ttl(cache_type)
            
            # Try to load from cache
            cached_result = cache_config.load_from_cache(cache_path)
            if cached_result is not None and cache_config.is_cache_valid(cache_path, ttl):
                return cached_result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            cache_config.save_to_cache(cache_path, result)
            
            return result
        return wrapper
    return decorator 