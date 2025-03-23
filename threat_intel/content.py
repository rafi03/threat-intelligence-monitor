#!/usr/bin/env python3
"""
Content extraction and processing for the Threat Intelligence Monitor.
"""

import logging
import re
from collections import Counter
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, Union

import feedparser
import requests
from bs4 import BeautifulSoup

from .utils import get_random_user_agent, create_request_headers, RateLimiter

logger = logging.getLogger("threat_intel")


class ContentExtractor:
    """
    Handles content extraction from security feeds and articles.
    """
    
    def __init__(self, delay: float = 1.0):
        """
        Initialize the content extractor.
        
        Args:
            delay: Base delay between requests in seconds
        """
        self.rate_limiter = RateLimiter(base_delay=delay)
        self.session = requests.Session()
        self.session.headers.update(create_request_headers())
    
    def parse_feed(self, url: str, feed_type: str = "rss") -> Dict[str, Any]:
        """
        Parse an RSS or Atom feed.
        
        Args:
            url: URL of the feed
            feed_type: Type of feed (rss, atom)
            
        Returns:
            Dictionary containing feed data
            
        Raises:
            ValueError: If feed cannot be parsed
        """
        # Rate limit requests to the feed provider
        self.rate_limiter.wait_if_needed(url)
        
        # Use a random user agent for each request
        headers = self.session.headers.copy()
        headers["User-Agent"] = get_random_user_agent()
        
        # Parse the feed
        feed = feedparser.parse(url, request_headers=headers)
        
        # Check for HTTP errors
        if hasattr(feed, 'status') and feed.status >= 400:
            raise ValueError(f"Feed returned HTTP {feed.status}")
                
        if not feed.entries:
            raise ValueError("Feed returned no entries")
        
        return feed
    
    def extract_published_date(self, entry: Any) -> datetime:
        """
        Extract published date from feed entry with fallbacks.
        
        Args:
            entry: Feed entry object
            
        Returns:
            Published date
        """
        if hasattr(entry, 'published_parsed') and entry.published_parsed:
            return datetime(*entry.published_parsed[:6])
        elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
            return datetime(*entry.updated_parsed[:6])
        elif hasattr(entry, 'created_parsed') and entry.created_parsed:
            return datetime(*entry.created_parsed[:6])
        else:
            # If no date found, use current time
            return datetime.now()
    
    def extract_entry_summary(self, entry: Any) -> str:
        """
        Extract summary from feed entry with fallbacks.
        
        Args:
            entry: Feed entry object
            
        Returns:
            Cleaned summary text
        """
        summary = ""
        
        # Try different fields that might contain the summary
        if hasattr(entry, 'summary'):
            summary = entry.summary
        elif hasattr(entry, 'description'):
            summary = entry.description
        elif hasattr(entry, 'content') and entry.content:
            # Some feeds use content instead of summary
            summary = entry.content[0].value
        else:
            summary = "No summary available"
        
        # Clean summary of HTML
        return BeautifulSoup(summary, "html.parser").get_text(separator=' ', strip=True)
    
    def extract_article_content(self, url: str) -> Tuple[str, List[str]]:
        """
        Extract article content using HTTP requests.
        
        Args:
            url: URL of the article
                
        Returns:
            Tuple of (full_content, keywords)
            
        Raises:
            requests.RequestException: If HTTP request fails
        """
        try:
            # Apply rate limiting by domain
            self.rate_limiter.wait_if_needed(url)
            
            # Ensure we have a fresh user agent
            self.session.headers.update({"User-Agent": get_random_user_agent()})
            
            # Make the request
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
            
            # Parse with BeautifulSoup
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Remove non-content elements
            for element in soup(["script", "style", "iframe", "nav", "footer", "header", "aside"]):
                element.decompose()
            
            # Try to find the main content
            content = self._find_main_content(soup)
            
            # Extract text and clean it
            if content:
                full_text = content.get_text("\n", strip=True)
                # Remove excessive whitespace
                full_text = re.sub(r'\n+', '\n', full_text)
                full_text = re.sub(r'\s+', ' ', full_text)
            else:
                full_text = "Content extraction failed"
            
            # Extract keywords
            keywords = self._extract_keywords(full_text)
            
            return full_text, keywords
            
        except Exception as e:
            logger.error(f"Error extracting content from {url}: {str(e)}")
            return f"Content extraction failed: {str(e)}", []
    
    def _find_main_content(self, soup: BeautifulSoup) -> Optional[Any]:
        """
        Find the main content element in a parsed HTML page.
        
        Args:
            soup: BeautifulSoup object
            
        Returns:
            BeautifulSoup element containing the main content
        """
        # General content selectors in order of preference
        content_selectors = [
            "article", 
            ".post-content", 
            ".entry-content",
            ".article-body",
            ".article-content",
            ".content-article",
            ".post__content",
            ".story-body",
            "main",
            "#content",
            ".content",
            "[itemprop='articleBody']",
            ".main-content",
            "#main-content"
        ]
        
        for selector in content_selectors:
            content = soup.select_one(selector)
            if content:
                return content
        
        # If no specific content container found, use body
        return soup.body
    
    def _extract_keywords(self, text: str, max_keywords: int = 10) -> List[str]:
        """
        Extract keywords from text using frequency analysis.
        
        Args:
            text: Text to analyze
            max_keywords: Maximum number of keywords to return
            
        Returns:
            List of keywords
        """
        # Common stopwords
        stopwords = {
            "the", "and", "is", "in", "it", "to", "of", "for", "with", "on",
            "that", "this", "be", "are", "as", "at", "have", "has", "was",
            "were", "from", "by", "not", "or", "an", "but", "a", "they",
            "we", "their", "our", "you", "i", "he", "she", "will", "would",
            "could", "can", "may", "should", "been", "his", "her", "them",
            "about", "there", "these", "those", "who", "what", "when", "where"
        }
        
        # Extract potential CVE IDs and other security identifiers
        security_ids = re.findall(r'\b(?:CVE|cve)-\d{4}-\d{4,}\b', text)
        
        # Tokenize single words (at least 3 chars)
        words = re.findall(r'\b[a-zA-Z][a-zA-Z0-9]{2,}\b', text.lower())
        filtered_words = [word for word in words if word not in stopwords]
        
        # Get most common words
        word_counts = Counter(filtered_words)
        
        # Add security IDs with higher weight
        for id_term in security_ids:
            word_counts[id_term] = word_counts.get(id_term, 0) + 5
        
        # Get the most common terms
        keywords = [word for word, count in word_counts.most_common(max_keywords)]
        
        return keywords