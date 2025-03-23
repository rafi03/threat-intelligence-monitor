#!/usr/bin/env python3
"""
Main monitoring functionality for the Threat Intelligence Monitor.
"""

import concurrent.futures
import csv
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple

from .content import ContentExtractor
from .database import ThreatDatabase
from .utils import DEFAULT_SECURITY_FEEDS, setup_logging

logger = logging.getLogger("threat_intel")


class ThreatIntelligenceMonitor:
    """
    Monitors security blogs and feeds for threat intelligence.
    
    This class handles the collection, processing, and analysis of security
    information from various cybersecurity news sources and feeds.
    """
    
    def __init__(self, feeds: Optional[List[Dict[str, Any]]] = None, 
                 db_path: str = "threat_intel.db", 
                 delay: float = 1.0, 
                 max_workers: int = 5,
                 verbose: bool = False):
        """
        Initialize the threat intelligence monitor.
        
        Args:
            feeds: List of feed dictionaries with name and URL
            db_path: Path to SQLite database file
            delay: Delay between requests in seconds to avoid rate limiting
            max_workers: Maximum number of concurrent workers for parallelization
            verbose: Whether to print detailed output for debugging
        """
        self.feeds = feeds or DEFAULT_SECURITY_FEEDS
        self.db_path = db_path
        self.delay = delay
        self.max_workers = max_workers
        
        # Set up logging if not already configured
        if not logger.handlers:
            setup_logging(verbose=verbose)
        
        # Prioritize feeds to process more important ones first
        self.feeds = sorted(self.feeds, key=lambda f: f.get("priority", 5), reverse=True)
        
        # Initialize content extractor
        self.extractor = ContentExtractor(delay=delay)
        
        # Initialize database
        self.db = ThreatDatabase(db_path=db_path)
    
    def update_feeds(self, days_back: int = 1) -> Dict[str, int]:
        """
        Update all feeds and store new articles using concurrent processing.
        
        Args:
            days_back: Only process articles from the last N days
            
        Returns:
            Statistics about the update process
        """
        stats = {
            "feeds_processed": 0,
            "new_articles": 0,
            "errors": 0
        }
        
        # Get all sources from database
        sources = self.db.get_sources()
        
        # Process each feed concurrently using ThreadPoolExecutor
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_source = {
                executor.submit(
                    self._process_feed, 
                    source["id"], 
                    source["name"], 
                    source["url"], 
                    source["type"], 
                    source.get("last_updated"), 
                    days_back
                ): source["name"]
                for source in sources
            }
            
            for future in concurrent.futures.as_completed(future_to_source):
                source_name = future_to_source[future]
                try:
                    result = future.result()
                    stats["feeds_processed"] += 1
                    stats["new_articles"] += result["new_articles"]
                    
                    logger.info(f"Processed {source_name}: {result['new_articles']} new articles")
                        
                except Exception as e:
                    stats["errors"] += 1
                    logger.error(f"Error processing {source_name}: {str(e)}")
        
        return stats
    
    def _process_feed(self, source_id: int, name: str, url: str, feed_type: str, 
                 last_updated: Optional[str], days_back: int) -> Dict[str, Any]:
        """
        Process a feed and store new articles.
        
        Args:
            source_id: Database ID of the source
            name: Name of the source
            url: URL of the feed
            feed_type: Type of feed (rss, atom)
            last_updated: Timestamp of last update
            days_back: Only process articles from the last N days
            
        Returns:
            Statistics about the processing
        """
        result = {
            "new_articles": 0,
            "source_id": source_id,
            "name": name
        }
        
        try:
            # Parse the feed
            feed = self.extractor.parse_feed(url, feed_type)
            
            logger.info(f"Feed {name} has {len(feed.entries)} entries")
            
            # Calculate cutoff date
            cutoff_date = datetime.now() - timedelta(days=days_back)
            
            # Update the last_updated timestamp for this source
            self.db.update_source_status(source_id, success=True)
            
            # Process each entry in the feed
            for entry in feed.entries:
                # Try to get the published date
                pub_date = self.extractor.extract_published_date(entry)
                
                # Skip if older than days_back
                if pub_date < cutoff_date:
                    continue
                
                # Basic entry data
                title = entry.title
                link = entry.link
                
                # Get summary
                summary = self.extractor.extract_entry_summary(entry)
                
                # Extract full content and keywords
                full_content, keywords = self.extractor.extract_article_content(link)
                
                # Store in database
                added = self.db.add_article(
                    source_id=source_id,
                    title=title,
                    url=link,
                    published_date=pub_date,
                    summary=summary,
                    full_content=full_content,
                    keywords=keywords
                )
                
                # Only increment counter if article was actually added
                if added:
                    result["new_articles"] += 1
            
            return result
            
        except Exception as e:
            logger.error(f"Error processing feed {name}: {str(e)}")
            
            # Record error in database
            self.db.update_source_status(source_id, success=False)
            raise
    
    def search_articles(self, query: Optional[str] = None, days: int = 7, 
                       limit: int = 20) -> List[Dict[str, Any]]:
        """
        Search for articles matching a query.
        
        Args:
            query: Search query
            days: Search in last N days
            limit: Maximum number of results
            
        Returns:
            List of matching articles
        """
        return self.db.search_articles(query=query, days=days, limit=limit)
    
    def get_trending_keywords(self, days: int = 3, limit: int = 10) -> List[Tuple[str, int]]:
        """
        Get trending keywords from recent articles.
        
        Args:
            days: Look at articles from last N days
            limit: Maximum number of keywords to return
            
        Returns:
            List of trending keywords with counts
        """
        keywords = self.db.get_article_keywords(days=days)
        return keywords[:limit]
    
    def export_to_json(self, articles: List[Dict[str, Any]], filename: str) -> None:
        """
        Export articles to JSON file.
        
        Args:
            articles: List of article dictionaries
            filename: Output filename
        """
        # Ensure directory exists
        os.makedirs(os.path.dirname(os.path.abspath(filename)) or '.', exist_ok=True)
        
        with open(filename, "w") as f:
            json.dump({
                "generated_at": datetime.now().isoformat(),
                "article_count": len(articles),
                "articles": articles
            }, f, indent=2)
        
        logger.info(f"Exported {len(articles)} articles to {filename}")
    
    def export_to_csv(self, articles: List[Dict[str, Any]], filename: str) -> None:
        """
        Export articles to CSV file.
        
        Args:
            articles: List of article dictionaries
            filename: Output filename
        """
        if not articles:
            logger.warning("No articles to export")
            return
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(os.path.abspath(filename)) or '.', exist_ok=True)
        
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, 
                fieldnames=["title", "source_name", "published_date", "url", "summary", "keywords"]
            )
            writer.writeheader()
            
            for article in articles:
                # Prepare a copy to avoid modifying the original
                article_copy = {k: v for k, v in article.items() if k in writer.fieldnames}
                writer.writerow(article_copy)
        
        logger.info(f"Exported {len(articles)} articles to {filename}")
    
    def print_articles(self, articles: List[Dict[str, Any]]) -> None:
        """
        Print articles in a formatted way.
        
        Args:
            articles: List of article dictionaries
        """
        if not articles:
            print("No articles found matching your criteria.")
            return
        
        print("\n===== THREAT INTELLIGENCE REPORT =====")
        print(f"Found {len(articles)} articles")
        print("=" * 40)
        
        for article in articles:
            # Format the date for better readability
            published_date = article["published_date"]
            if "T" in published_date:  # ISO format
                published_date = published_date.split("T")[0]
            
            # Print article details with formatting
            print(f"\n{article['title']}")
            print(f"Source: {article['source_name']} | Date: {published_date}")
            print(f"URL: {article['url']}")
            
            # Format summary with wrapping for better readability
            if "summary" in article and article["summary"]:
                wrapped_summary = '\n'.join([line.strip() for line in article["summary"].splitlines()])
                print(f"\nSummary:\n{wrapped_summary}")
            
            # Show keywords if available
            if "keywords" in article and article["keywords"]:
                keywords = article["keywords"].split(",")
                print(f"\nKeywords: {', '.join(keywords)}")
            
            print("-" * 40)