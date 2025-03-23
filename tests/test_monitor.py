#!/usr/bin/env python3
"""
Unit tests for the Threat Intelligence Monitor.
"""

import os
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, call

from threat_intel.monitor import ThreatIntelligenceMonitor
from threat_intel.database import ThreatDatabase
from threat_intel.content import ContentExtractor


class MockMonitor(ThreatIntelligenceMonitor):
    """A special version of the monitor that's easier to test."""
    
    def _process_feed(self, source_id, name, url, feed_type, last_updated, days_back):
        """
        Override the _process_feed method to return predetermined results.
        """
        return {
            "new_articles": 1,  # Each feed adds 1 article
            "source_id": source_id,
            "name": name
        }


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
            feeds=self.test_feeds,  # Use our test feeds, not the default ones
            db_path=self.db_path,
            delay=0.1,  # Fast for testing
            max_workers=2,
            verbose=False
        )
        
        # Also create a mock monitor for certain tests
        self.mock_monitor = MockMonitor(
            feeds=self.test_feeds,
            db_path=self.db_path,
            delay=0.1,
            max_workers=2,
            verbose=False
        )
    
    def tearDown(self):
        """Clean up after tests."""
        # Remove test database
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
    
    @patch('threat_intel.database.ThreatDatabase.get_sources')
    def test_update_feeds(self, mock_get_sources):
        """Test updating feeds using our MockMonitor."""
        # Mock the database sources to return only our test feeds
        mock_get_sources.return_value = [
            {"id": 1, "name": "Test Feed 1", "url": "https://example.com/feed1.xml", "type": "rss"},
            {"id": 2, "name": "Test Feed 2", "url": "https://example.com/feed2.xml", "type": "atom"}
        ]
        
        # Run the update with our mock monitor that returns predetermined results
        stats = self.mock_monitor.update_feeds(days_back=7)
        
        # Verify results
        self.assertEqual(stats["feeds_processed"], 2)
        self.assertEqual(stats["new_articles"], 2)  # 1 from each feed
        self.assertEqual(stats["errors"], 0)
    
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