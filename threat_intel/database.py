#!/usr/bin/env python3
"""
Database management for the Threat Intelligence Monitor.
"""

import logging
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union

from .utils import DEFAULT_SECURITY_FEEDS

logger = logging.getLogger("threat_intel")


class DatabaseManager:
    """Context manager for database operations."""
    
    def __init__(self, db_path: str):
        """
        Initialize the database manager.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self.conn = None
        self.cursor = None
    
    def __enter__(self):
        self.conn = sqlite3.connect(self.db_path)
        # Enable foreign keys constraint enforcement
        self.conn.execute("PRAGMA foreign_keys = ON")
        # Add timeout to prevent database locked errors
        self.conn.execute("PRAGMA busy_timeout = 30000")  # 30 seconds
        
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        return self.cursor
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            if exc_type is None:
                self.conn.commit()
            else:
                self.conn.rollback()
            self.conn.close()
        return False  # Let exceptions propagate


class ThreatDatabase:
    """Handles all database operations for the threat intelligence monitor."""
    
    def __init__(self, db_path: str = "threat_intel.db"):
        """
        Initialize the database.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self) -> None:
        """
        Initialize SQLite database for storing articles and sources.
        
        Creates the necessary tables if they don't exist and ensures all 
        configured feed sources are added to the database.
        """
        try:
            with DatabaseManager(self.db_path) as cursor:
                # Create tables if they don't exist
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS sources (
                    id INTEGER PRIMARY KEY,
                    name TEXT UNIQUE,
                    url TEXT,
                    type TEXT,
                    last_updated TIMESTAMP,
                    error_count INTEGER DEFAULT 0
                )
                ''')
                
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS articles (
                    id INTEGER PRIMARY KEY,
                    source_id INTEGER,
                    title TEXT,
                    url TEXT UNIQUE,
                    published_date TIMESTAMP,
                    retrieved_date TIMESTAMP,
                    summary TEXT,
                    full_content TEXT,
                    keywords TEXT,
                    FOREIGN KEY (source_id) REFERENCES sources (id)
                )
                ''')
                
                # Create indexes for better query performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_articles_pubdate ON articles(published_date)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_articles_source ON articles(source_id)')
                
                # Make sure all our sources are in the database
                for feed in DEFAULT_SECURITY_FEEDS:
                    cursor.execute(
                        "INSERT OR IGNORE INTO sources (name, url, type) VALUES (?, ?, ?)",
                        (feed["name"], feed["url"], feed.get("type", "rss"))
                    )
            
            logger.info(f"Database initialized at {self.db_path}")
                
        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")
            raise
    
    def get_sources(self) -> List[Dict[str, Any]]:
        """
        Get all sources from the database.
        
        Returns:
            List of source dictionaries
        """
        with DatabaseManager(self.db_path) as cursor:
            cursor.execute("SELECT id, name, url, type, last_updated FROM sources")
            sources = [dict(row) for row in cursor.fetchall()]
        return sources
    
    def update_source_status(self, source_id: int, success: bool = True) -> None:
        """
        Update the status of a source.
        
        Args:
            source_id: ID of the source to update
            success: Whether the update was successful
        """
        with DatabaseManager(self.db_path) as cursor:
            if success:
                cursor.execute(
                    "UPDATE sources SET last_updated = ?, error_count = 0 WHERE id = ?",
                    (datetime.now().isoformat(), source_id)
                )
            else:
                cursor.execute(
                    "UPDATE sources SET error_count = error_count + 1 WHERE id = ?",
                    (source_id,)
                )
    
    def add_article(self, source_id: int, title: str, url: str, 
                    published_date: datetime, summary: str, 
                    full_content: str, keywords: List[str]) -> bool:
        """
        Add a new article to the database.
        
        Args:
            source_id: ID of the source
            title: Article title
            url: Article URL
            published_date: Date the article was published
            summary: Article summary
            full_content: Full article content
            keywords: List of keywords
            
        Returns:
            Whether the article was added (False if it already exists)
        """
        try:
            with DatabaseManager(self.db_path) as cursor:
                # Check if article already exists
                cursor.execute("SELECT id FROM articles WHERE url = ?", (url,))
                if cursor.fetchone():
                    return False
                
                # Add the article
                cursor.execute(
                    """
                    INSERT INTO articles 
                    (source_id, title, url, published_date, retrieved_date, summary, full_content, keywords)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        source_id, 
                        title, 
                        url, 
                        published_date.isoformat(), 
                        datetime.now().isoformat(),
                        summary,
                        full_content,
                        ",".join(keywords)
                    )
                )
                return True
                
        except sqlite3.Error as e:
            logger.error(f"Error adding article {url}: {e}")
            return False
    
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
        with DatabaseManager(self.db_path) as cursor:
            # Calculate date cutoff
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            if query:
                # Clean and prepare the query
                query = query.strip()
                search_term = f"%{query}%"
                
                # Search across multiple fields
                sql = """
                SELECT a.id, a.title, a.url, a.published_date, a.summary, a.keywords, s.name as source_name
                FROM articles a
                JOIN sources s ON a.source_id = s.id
                WHERE a.published_date > ?
                  AND (
                    a.title LIKE ? 
                    OR a.summary LIKE ? 
                    OR a.full_content LIKE ?
                    OR a.keywords LIKE ?
                  )
                ORDER BY a.published_date DESC
                LIMIT ?
                """
                cursor.execute(sql, (cutoff_date, search_term, search_term, search_term, search_term, limit))
            else:
                # Return recent articles if no query
                sql = """
                SELECT a.id, a.title, a.url, a.published_date, a.summary, a.keywords, s.name as source_name
                FROM articles a
                JOIN sources s ON a.source_id = s.id
                WHERE a.published_date > ?
                ORDER BY a.published_date DESC
                LIMIT ?
                """
                cursor.execute(sql, (cutoff_date, limit))
            
            articles = [dict(row) for row in cursor.fetchall()]
        
        return articles
    
    def get_article_keywords(self, days: int = 3) -> List[Tuple[str, int]]:
        """
        Get keywords from recent articles for trend analysis.
        
        Args:
            days: Look at articles from last N days
            
        Returns:
            List of (keyword, count) tuples
        """
        with DatabaseManager(self.db_path) as cursor:
            # Calculate date cutoff
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            # Get keywords from recent articles
            cursor.execute(
                "SELECT keywords FROM articles WHERE published_date > ?",
                (cutoff_date,)
            )
            
            keyword_rows = cursor.fetchall()
            
        # Build a list of all keywords
        all_keywords = []
        for row in keyword_rows:
            if row["keywords"]:
                all_keywords.extend(row["keywords"].split(","))
        
        # Count occurrences
        keyword_counts = {}
        for keyword in all_keywords:
            keyword_counts[keyword] = keyword_counts.get(keyword, 0) + 1
        
        # Sort by count
        sorted_keywords = sorted(keyword_counts.items(), key=lambda x: x[1], reverse=True)
        
        return sorted_keywords