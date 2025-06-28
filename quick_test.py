#!/usr/bin/env python3
"""
Quick test to verify RSS feed fixes
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def quick_test():
    """Quick test of RSS feeds."""
    try:
        from data_sources.rss_feeds import RSSFeedProcessor
        
        print("Quick RSS Feed Test...")
        processor = RSSFeedProcessor()
        
        # Test a few individual feeds
        test_feeds = ['the_hackers_news', 'schneier_on_security', 'the_record']
        
        for feed_id in test_feeds:
            if feed_id in processor.feeds:
                feed_config = processor.feeds[feed_id]
                print(f"\nTesting {feed_config['name']}...")
                try:
                    articles = processor._process_feed(feed_config, 24)
                    print(f"  Articles found: {len(articles)}")
                    if articles:
                        print(f"  Sample: {articles[0].get('title', 'N/A')[:60]}...")
                except Exception as e:
                    print(f"  Error: {e}")
        
        # Test overall processing
        print(f"\n=== Overall Processing ===")
        articles = processor.process_security_news(max_age_hours=24, use_cache=False)
        print(f"Total articles: {len(articles)}")
        
        if articles:
            print("\nSample articles:")
            for i, article in enumerate(articles[:3]):
                print(f"  {i+1}. {article.get('title', 'N/A')[:50]}... ({article.get('source', 'N/A')})")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    quick_test() 