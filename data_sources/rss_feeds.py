"""
RSS Feed Processor

This module processes RSS feeds from security news sources and extracts
threat intelligence information.
"""

import feedparser
import requests
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import re
import json
from bs4 import BeautifulSoup
import threading
import time

logger = logging.getLogger(__name__)

class RSSFeedProcessor:
    """Process RSS feeds for security news and threat intelligence."""
    
    def __init__(self):
        """Initialize RSS feed processor."""
        self.feeds = {
            'the_hackers_news': {
                'url': 'https://feeds.feedburner.com/TheHackersNews',
                'name': 'The Hacker News',
                'category': 'security_news',
                'enabled': True
            },
            'bleeping_computer': {
                'url': 'https://www.bleepingcomputer.com/feed/',
                'name': 'Bleeping Computer',
                'category': 'security_news',
                'enabled': True
            },
            'threatpost': {
                'url': 'https://threatpost.com/feed/',
                'name': 'Threatpost',
                'category': 'security_news',
                'enabled': True
            },
            'security_week': {
                'url': 'https://www.securityweek.com/feed/',
                'name': 'Security Week',
                'category': 'security_news',
                'enabled': True
            },
            'krebs_on_security': {
                'url': 'https://krebsonsecurity.com/feed/',
                'name': 'Krebs on Security',
                'category': 'security_news',
                'enabled': True
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
    
    def process_security_news(self, max_age_hours: int = 24) -> List[Dict]:
        """Process security news from RSS feeds."""
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
        
        # Sort by publication date
        all_articles.sort(key=lambda x: x.get('published_date', ''), reverse=True)
        
        return all_articles
    
    def _process_feed(self, feed_config: Dict, max_age_hours: int) -> List[Dict]:
        """Process a single RSS feed."""
        try:
            # Parse RSS feed
            feed = feedparser.parse(feed_config['url'])
            
            if feed.bozo:
                logger.warning(f"Feed parsing error for {feed_config['name']}")
            
            articles = []
            cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
            
            for entry in feed.entries:
                try:
                    # Parse publication date
                    pub_date = self._parse_date(entry.get('published', ''))
                    if pub_date and pub_date < cutoff_time:
                        continue
                    
                    # Extract article content
                    article = self._extract_article_info(entry, feed_config)
                    
                    if article and article['url'] not in self.processed_articles:
                        # Extract threat intelligence
                        threat_intel = self._extract_threat_intelligence(article['content'])
                        article['threat_intelligence'] = threat_intel
                        
                        articles.append(article)
                        self.processed_articles.add(article['url'])
                
                except Exception as e:
                    logger.error(f"Error processing article: {e}")
                    continue
            
            return articles
            
        except Exception as e:
            logger.error(f"Error processing feed {feed_config['name']}: {e}")
            return []
    
    def _parse_date(self, date_string: str) -> Optional[datetime]:
        """Parse date string from RSS feed."""
        try:
            # Try different date formats
            date_formats = [
                '%a, %d %b %Y %H:%M:%S %z',
                '%a, %d %b %Y %H:%M:%S %Z',
                '%Y-%m-%dT%H:%M:%S%z',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%d %H:%M:%S'
            ]
            
            for fmt in date_formats:
                try:
                    return datetime.strptime(date_string, fmt)
                except ValueError:
                    continue
            
            # If all formats fail, try feedparser's date parsing
            parsed = feedparser._parse_date(date_string)
            if parsed:
                return datetime(*parsed[:6])
            
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
    
    def get_latest_articles(self, limit: int = 50) -> List[Dict]:
        """Get latest security articles."""
        return self.process_security_news(max_age_hours=24)[:limit]
    
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