"""
RSS Feed Processor

This module processes RSS feeds from security news sources and extracts
threat intelligence information.
"""

import feedparser
import requests
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta, timezone
import re
import json
from bs4 import BeautifulSoup
import threading
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

class RSSFeedProcessor:
    """Process RSS feeds for security news and threat intelligence."""
    
    CACHE_TTL_SECONDS = 300  # 5 minutes
    BACKGROUND_REFRESH_INTERVAL = 600  # 10 minutes
    
    def __init__(self):
        """Initialize RSS feed processor."""
        self.feeds = {
            # High-quality feeds from Awesome Threat Intel Blogs
            'the_hackers_news': {
                'url': 'https://feeds.feedburner.com/TheHackersNews',
                'name': 'The Hacker News',
                'category': 'security_news',
                'enabled': True
            },
            'krebs_on_security': {
                'url': 'https://krebsonsecurity.com/feed/',
                'name': 'Krebs on Security',
                'category': 'security_news',
                'enabled': True
            },
            'schneier_on_security': {
                'url': 'https://www.schneier.com/feed/',
                'name': 'Schneier on Security',
                'category': 'security_news',
                'enabled': True
            },
            'threatpost': {
                'url': 'https://threatpost.com/feed/',
                'name': 'Threatpost',
                'category': 'security_news',
                'enabled': True
            },
            'the_record': {
                'url': 'https://therecord.media/feed/',
                'name': 'The Record',
                'category': 'security_news',
                'enabled': True
            },
            'securelist': {
                'url': 'https://securelist.com/feed/',
                'name': 'Securelist',
                'category': 'security_news',
                'enabled': True
            },
            'welivesecurity': {
                'url': 'https://www.welivesecurity.com/en/rss/feed/',
                'name': 'We Live Security',
                'category': 'security_news',
                'enabled': True
            },
            'sophos_news': {
                'url': 'https://news.sophos.com/en-us/category/threat-research/feed/',
                'name': 'Sophos Threat Research',
                'category': 'security_news',
                'enabled': True
            },
            'sentinelone_labs': {
                'url': 'https://www.sentinelone.com/labs/feed/',
                'name': 'SentinelOne Labs',
                'category': 'security_news',
                'enabled': True
            },
            'crowdstrike_blog': {
                'url': 'https://www.crowdstrike.com/blog/feed/',
                'name': 'CrowdStrike Blog',
                'category': 'security_news',
                'enabled': True
            },
            'malwarebytes_labs': {
                'url': 'https://blog.malwarebytes.com/feed/',
                'name': 'Malwarebytes Labs',
                'category': 'security_news',
                'enabled': True
            },
            'microsoft_security': {
                'url': 'https://api.msrc.microsoft.com/update-guide/rss',
                'name': 'Microsoft Security Response Center',
                'category': 'security_news',
                'enabled': True
            },
            'google_project_zero': {
                'url': 'https://googleprojectzero.blogspot.com/feeds/posts/default',
                'name': 'Google Project Zero',
                'category': 'security_news',
                'enabled': True
            },
            'naked_security': {
                'url': 'https://nakedsecurity.sophos.com/feed/',
                'name': 'Naked Security',
                'category': 'security_news',
                'enabled': False  # Disabled due to XML parsing errors
            },
            'security_week': {
                'url': 'https://www.securityweek.com/feed/',
                'name': 'Security Week',
                'category': 'security_news',
                'enabled': False  # Keep disabled due to 403 errors
            },
            'bleeping_computer': {
                'url': 'https://www.bleepingcomputer.com/feed/',
                'name': 'Bleeping Computer',
                'category': 'security_news',
                'enabled': False  # Keep disabled due to 403 errors
            }
        }
        
        self.processed_articles = set()
        self.threat_keywords = [
            'malware', 'ransomware', 'phishing', 'breach', 'hack', 'attack',
            'vulnerability', 'exploit', 'threat', 'cyber', 'security',
            'apt', 'botnet', 'trojan', 'virus', 'spyware', 'backdoor',
            'cve', 'zero-day', 'data breach', 'cyber attack'
        ]
        
        self.malware_families = [
            'emotet', 'trickbot', 'qakbot', 'ryuk', 'conti', 'revil',
            'wannacry', 'notpetya', 'locky', 'cerber', 'cryptolocker',
            'zeus', 'spyeye', 'citadel', 'dridex', 'ursnif'
        ]
        
        self.threat_actors = [
            'apt29', 'apt28', 'apt41', 'apt40', 'lazarus', 'sandworm',
            'cozy bear', 'fancy bear', 'wizard spider', 'silence',
            'cobalt group', 'fin7', 'carbanak', 'darkhydrus'
        ]
        
        logger.info("RSS Feed Processor initialized successfully")
        
        # Enhanced caching attributes
        self._news_cache = None
        self._news_cache_time = 0
        self._cache_lock = threading.Lock()
        self._background_thread = None
        self._stop_background = False
        
        # Start background refresh thread
        self._start_background_refresh()
    
    def _start_background_refresh(self):
        """Start background thread to refresh news cache."""
        if self._background_thread is None or not self._background_thread.is_alive():
            self._stop_background = False
            self._background_thread = threading.Thread(target=self._background_refresh_worker, daemon=True)
            self._background_thread.start()
            logger.info("Started background news refresh thread")
    
    def _background_refresh_worker(self):
        """Background worker that refreshes news cache periodically."""
        while not self._stop_background:
            try:
                # Initial load
                if self._news_cache is None:
                    logger.info("Performing initial news cache load")
                    self.process_security_news(use_cache=False)
                
                # Wait for refresh interval
                time.sleep(self.BACKGROUND_REFRESH_INTERVAL)
                
                if not self._stop_background:
                    logger.info("Performing background news cache refresh")
                    self.process_security_news(use_cache=False)
                    
            except Exception as e:
                logger.error(f"Error in background news refresh: {e}")
                time.sleep(60)  # Wait 1 minute before retrying
    
    def stop_background_refresh(self):
        """Stop the background refresh thread."""
        self._stop_background = True
        if self._background_thread and self._background_thread.is_alive():
            self._background_thread.join(timeout=5)
            logger.info("Stopped background news refresh thread")
    
    def get_cached_news(self) -> List[Dict]:
        """Get cached news articles immediately without processing."""
        with self._cache_lock:
            if self._news_cache is not None:
                return self._news_cache.copy()
            return []
    
    def is_cache_fresh(self) -> bool:
        """Check if the cache is fresh (within TTL)."""
        now = time.time()
        return (
            self._news_cache is not None and
            now - self._news_cache_time < self.CACHE_TTL_SECONDS
        )
    
    def get_cache_status(self) -> Dict:
        """Get cache status information."""
        now = time.time()
        with self._cache_lock:
            return {
                'has_cache': self._news_cache is not None,
                'cache_age_seconds': now - self._news_cache_time if self._news_cache_time > 0 else None,
                'cache_ttl_seconds': self.CACHE_TTL_SECONDS,
                'is_fresh': self.is_cache_fresh(),
                'article_count': len(self._news_cache) if self._news_cache else 0,
                'background_thread_alive': self._background_thread.is_alive() if self._background_thread else False
            }
    
    def process_security_news(self, max_age_hours: int = 24, use_cache: bool = True) -> List[Dict]:
        """Process security news from RSS feeds, with caching."""
        now = time.time()
        if use_cache:
            with self._cache_lock:
                if (
                    self._news_cache is not None and
                    now - self._news_cache_time < self.CACHE_TTL_SECONDS
                ):
                    logger.debug("Returning cached security news articles.")
                    return self._news_cache
        
        # Set flag to track processed articles for deduplication
        self._processing_all_feeds = True
        
        all_articles = []
        for feed_id, feed_config in self.feeds.items():
            if not feed_config['enabled']:
                continue
            
            try:
                articles = self._process_feed(feed_config, max_age_hours)
                all_articles.extend(articles)
                logger.info(f"Processed {len(articles)} articles from {feed_config['name']}")
                
            except Exception as e:
                logger.error(f"Error processing feed {feed_id}: {e}")
        
        # Clear the flag
        self._processing_all_feeds = False
        
        # Sort by publication date
        all_articles.sort(key=lambda x: x.get('published_date', ''), reverse=True)
        
        # Update cache
        if use_cache:
            with self._cache_lock:
                self._news_cache = all_articles
                self._news_cache_time = now
        
        return all_articles
    
    def _process_feed(self, feed_config: Dict, max_age_hours: int) -> List[Dict]:
        """Process a single RSS feed."""
        try:
            # Parse RSS feed with timeout
            # Configure retry strategy
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session = requests.Session()
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            
            # Fetch feed with timeout
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'application/rss+xml, application/xml, text/xml, */*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            response = session.get(feed_config['url'], timeout=10, headers=headers)
            response.raise_for_status()
            
            # Parse the feed content
            feed = feedparser.parse(response.content)
            
            if feed.bozo:
                logger.warning(f"Feed parsing error for {feed_config['name']}: {feed.bozo_exception}")
            
            articles = []
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
            
            for entry in feed.entries:
                try:
                    # Parse publication date
                    pub_date = self._parse_date(entry.get('published', ''))
                    if pub_date:
                        if pub_date.tzinfo is None:
                            pub_date = pub_date.replace(tzinfo=timezone.utc)
                        else:
                            pub_date = pub_date.astimezone(timezone.utc)
                        if pub_date < cutoff_time:
                            continue
                    
                    # Extract article content
                    article = self._extract_article_info(entry, feed_config)
                    
                    if article:
                        # Extract threat intelligence
                        threat_intel = self._extract_threat_intelligence(article['content'])
                        article['threat_intelligence'] = threat_intel
                        
                        articles.append(article)
                        # Only track processed articles for overall processing, not individual feed tests
                        if hasattr(self, '_processing_all_feeds') and self._processing_all_feeds:
                            self.processed_articles.add(article['url'])
                
                except Exception as e:
                    logger.error(f"Error processing article: {e}")
                    continue
            
            logger.info(f"Successfully processed {len(articles)} articles from {feed_config['name']}")
            return articles
            
        except requests.exceptions.Timeout:
            logger.error(f"Timeout processing feed {feed_config['name']}")
            return []
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error processing feed {feed_config['name']}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error processing feed {feed_config['name']}: {e}")
            return []
    
    def _parse_date(self, date_string: str) -> Optional[datetime]:
        """Parse date string from RSS feed and return a timezone-aware datetime (UTC) if possible."""
        try:
            # Try different date formats
            date_formats = [
                '%a, %d %b %Y %H:%M:%S %z',
                '%a, %d %b %Y %H:%M:%S %Z',
                '%Y-%m-%dT%H:%M:%S%z',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%d %H:%M:%S',
                '%b %d, %Y %H:%M:%S%z',  # Added format for CrowdStrike
                '%Y-%m-%dT%H:%M:%S.%f%z'  # Added format for Google Project Zero
            ]
            
            for fmt in date_formats:
                try:
                    dt = datetime.strptime(date_string, fmt)
                    if fmt.endswith('%z') or fmt.endswith('%Z') or 'T' in fmt:
                        # If parsed as aware, convert to UTC
                        if dt.tzinfo is not None:
                            return dt.astimezone(timezone.utc)
                    # If parsed as naive, make aware (UTC)
                    return dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
            
            # If all formats fail, try using dateutil parser as fallback
            try:
                from dateutil import parser
                dt = parser.parse(date_string)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except:
                pass
            
        except Exception as e:
            logger.error(f"Error parsing date '{date_string}': {e}")
        
        return None
    
    def _extract_article_info(self, entry, feed_config: Dict) -> Optional[Dict]:
        """Extract article information from RSS entry."""
        try:
            # Get content
            content = entry.get('summary', '')
            if not content and 'content' in entry:
                content = entry.content[0].value
            
            # Clean HTML tags
            content = self._clean_html(content)
            
            # Get full article content if possible
            full_content = self._get_full_content(entry.get('link', ''))
            if full_content:
                content = full_content
            
            article = {
                'title': entry.get('title', ''),
                'url': entry.get('link', ''),
                'content': content,
                'summary': entry.get('summary', ''),
                'author': entry.get('author', ''),
                'published_date': entry.get('published', ''),
                'source': feed_config['name'],
                'category': feed_config['category'],
                'tags': entry.get('tags', [])
            }
            
            return article
            
        except Exception as e:
            logger.error(f"Error extracting article info: {e}")
            return None
    
    def _clean_html(self, html_content: str) -> str:
        """Clean HTML tags from content."""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            return soup.get_text()
        except Exception:
            # Fallback to regex if BeautifulSoup fails
            return re.sub(r'<[^>]+>', '', html_content)
    
    def _get_full_content(self, url: str) -> Optional[str]:
        """Get full article content from URL."""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Try to find main content
                content_selectors = [
                    'article',
                    '.post-content',
                    '.entry-content',
                    '.article-content',
                    '.content',
                    'main'
                ]
                
                for selector in content_selectors:
                    content = soup.select_one(selector)
                    if content:
                        return content.get_text()
                
                # Fallback to body text
                return soup.get_text()
            
        except Exception as e:
            logger.debug(f"Error getting full content from {url}: {e}")
        
        return None
    
    def _extract_threat_intelligence(self, content: str) -> Dict:
        """Extract threat intelligence from article content."""
        threat_intel = {
            'keywords_found': [],
            'malware_mentioned': [],
            'threat_actors_mentioned': [],
            'vulnerabilities_mentioned': [],
            'iocs_found': [],
            'threat_score': 0,
            'categories': []
        }
        
        content_lower = content.lower()
        
        # Find threat keywords
        for keyword in self.threat_keywords:
            if keyword.lower() in content_lower:
                threat_intel['keywords_found'].append(keyword)
        
        # Find malware families
        for malware in self.malware_families:
            if malware.lower() in content_lower:
                threat_intel['malware_mentioned'].append(malware)
        
        # Find threat actors
        for actor in self.threat_actors:
            if actor.lower() in content_lower:
                threat_intel['threat_actors_mentioned'].append(actor)
        
        # Find CVE references
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, content, re.IGNORECASE)
        threat_intel['vulnerabilities_mentioned'] = list(set(cves))
        
        # Find IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, content)
        threat_intel['iocs_found'].extend(ips)
        
        # Find domains
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, content)
        threat_intel['iocs_found'].extend(domains)
        
        # Find file hashes
        hash_patterns = [
            r'\b[a-fA-F0-9]{32}\b',  # MD5
            r'\b[a-fA-F0-9]{40}\b',  # SHA1
            r'\b[a-fA-F0-9]{64}\b'   # SHA256
        ]
        
        for pattern in hash_patterns:
            hashes = re.findall(pattern, content)
            threat_intel['iocs_found'].extend(hashes)
        
        # Calculate threat score
        threat_intel['threat_score'] = self._calculate_threat_score(threat_intel)
        
        # Determine categories
        threat_intel['categories'] = self._determine_categories(threat_intel)
        
        return threat_intel
    
    def _calculate_threat_score(self, threat_intel: Dict) -> int:
        """Calculate threat score based on extracted intelligence."""
        score = 0
        
        # Base score from keywords
        score += len(threat_intel['keywords_found']) * 2
        
        # Malware families (high impact)
        score += len(threat_intel['malware_mentioned']) * 15
        
        # Threat actors (high impact)
        score += len(threat_intel['threat_actors_mentioned']) * 20
        
        # Vulnerabilities
        score += len(threat_intel['vulnerabilities_mentioned']) * 10
        
        # IOCs
        score += len(threat_intel['iocs_found']) * 5
        
        return min(score, 100)
    
    def _determine_categories(self, threat_intel: Dict) -> List[str]:
        """Determine article categories based on threat intelligence."""
        categories = []
        
        if threat_intel['malware_mentioned']:
            categories.append('malware')
        
        if threat_intel['threat_actors_mentioned']:
            categories.append('apt')
        
        if threat_intel['vulnerabilities_mentioned']:
            categories.append('vulnerability')
        
        if threat_intel['iocs_found']:
            categories.append('ioc')
        
        if 'breach' in threat_intel['keywords_found']:
            categories.append('data_breach')
        
        if 'ransomware' in threat_intel['keywords_found']:
            categories.append('ransomware')
        
        if 'phishing' in threat_intel['keywords_found']:
            categories.append('phishing')
        
        return list(set(categories))
    
    def invalidate_news_cache(self):
        """Invalidate the news cache (force refresh on next request)."""
        with self._cache_lock:
            self._news_cache = None
            self._news_cache_time = 0
    
    def get_latest_articles(self, limit: int = 50, use_cache: bool = True) -> List[Dict]:
        """Get latest security articles (cached)."""
        return self.process_security_news(max_age_hours=24, use_cache=use_cache)[:limit]
    
    def get_articles_by_category(self, category: str, limit: int = 20) -> List[Dict]:
        """Get articles by category."""
        all_articles = self.process_security_news(max_age_hours=168)  # Last week
        
        filtered_articles = []
        for article in all_articles:
            if category in article.get('threat_intelligence', {}).get('categories', []):
                filtered_articles.append(article)
                if len(filtered_articles) >= limit:
                    break
        
        return filtered_articles
    
    def search_articles(self, query: str, limit: int = 20) -> List[Dict]:
        """Search articles by query."""
        all_articles = self.process_security_news(max_age_hours=168)  # Last week
        
        query_lower = query.lower()
        matching_articles = []
        
        for article in all_articles:
            if (query_lower in article['title'].lower() or 
                query_lower in article['content'].lower()):
                matching_articles.append(article)
                if len(matching_articles) >= limit:
                    break
        
        return matching_articles

# Global instance - lazy loaded
_rss_processor_instance = None

def get_rss_processor():
    """Get the global RSS processor instance (lazy loaded)."""
    global _rss_processor_instance
    if _rss_processor_instance is None:
        _rss_processor_instance = RSSFeedProcessor()
    return _rss_processor_instance 