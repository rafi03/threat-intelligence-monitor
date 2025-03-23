#!/usr/bin/env python3
"""
Unit tests for the Threat Intelligence Monitor.
"""

import os
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from threat_intel.monitor import ThreatIntelligenceMonitor
from threat_intel.database import ThreatDatabase
from threat_intel.content import ContentExtractor


class TestThreatIntelligenceMonitor(unittest.TestCase):
    """Test cases for the ThreatIntelligenceMonitor class."""
    
    def setUp(self):
        """Set up test environment."""
        # Use a temporary database for testing
        self.db_path = "test_threat_intel.db"
        self.test_feeds = [
            {
                "name": "Test Feed 1",
                "url": "https://example.com/feed1.xml",
                "type": "rss",
                "priority": 10
            },
            {
                "name": "Test Feed 2",
                "url": "https://example.com/feed2.xml",
                "type": "atom",
                "priority": 5
            }
        ]
        
        # Create the monitor with test configuration
        self.monitor = ThreatIntelligenceMonitor(
            feeds=self.test_feeds,
            db_path=self.db_path,
            delay=0.1,  # Fast for testing
            max_workers=2,
            verbose=False
        )
    
    def tearDown(self):
        """Clean up after tests."""
        # Remove test database
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
    
    @patch('threat_intel.content.ContentExtractor.parse_feed')
    @patch('threat_intel.content.ContentExtractor.extract_article_content')
    def test_update_feeds(self, mock_extract_content, mock_parse_feed):
        """Test updating feeds."""
        # Mock feed parsing
        mock_entry = MagicMock()
        mock_entry.title = "Test Article"
        mock_entry.link = "https://example.com/article1"
        mock_entry.published_parsed = (2023, 1, 1, 12, 0, 0, 0, 0, 0)
        
        mock_feed = MagicMock()
        mock_feed.entries = [mock_entry]
        mock_parse_feed.return_value = mock_feed
        
        # Mock content extraction
        mock_extract_content.return_value = ("Test content", ["keyword1", "keyword2"])
        
        # Run the update
        stats = self.monitor.update_feeds(days_back=7)
        
        # Verify results
        self.assertEqual(stats["feeds_processed"], 2)
        self.assertEqual(stats["new_articles"], 2)  # 1 from each feed
        self.assertEqual(stats["errors"], 0)
        
        # Verify database has the articles
        articles = self.monitor.search_articles(days=7)
        self.assertEqual(len(articles), 2)
    
    def test_search_articles(self):
        """Test searching articles."""
        # Mock some articles in the database
        with patch.object(ThreatDatabase, 'search_articles') as mock_search:
            mock_articles = [
                {
                    "id": 1,
                    "title": "Test Security Article",
                    "url": "https://example.com/article1",
                    "published_date": datetime.now().isoformat(),
                    "source_name": "Test Source",
                    "summary": "This is a test summary",
                    "keywords": "test,security,article"
                }
            ]
            mock_search.return_value = mock_articles
            
            # Search for articles
            results = self.monitor.search_articles(query="security", days=7)
            
            # Verify results
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["title"], "Test Security Article")
    
    def test_trending_keywords(self):
        """Test extracting trending keywords."""
        # Mock some keywords in the database
        with patch.object(ThreatDatabase, 'get_article_keywords') as mock_keywords:
            mock_keywords.return_value = [
                ("security", 5),
                ("vulnerability", 3),
                ("exploit", 2)
            ]
            
            # Get trending keywords
            trends = self.monitor.get_trending_keywords(days=3, limit=3)
            
            # Verify results
            self.assertEqual(len(trends), 3)
            self.assertEqual(trends[0][0], "security")
            self.assertEqual(trends[0][1], 5)


if __name__ == '__main__':
    unittest.main()