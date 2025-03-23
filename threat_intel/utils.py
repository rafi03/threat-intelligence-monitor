#!/usr/bin/env python3
"""
Utility functions and classes for the Threat Intelligence Monitor.
"""

import logging
import os
import random
import time
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse

# Common User-Agent strings for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
]

# Default security feeds
DEFAULT_SECURITY_FEEDS = [
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "type": "rss",
        "priority": 10
    },
    {
        "name": "Schneier on Security",
        "url": "https://www.schneier.com/feed/atom/",
        "type": "atom",
        "priority": 9
    },
    {
        "name": "US-CERT Advisories",
        "url": "https://www.cisa.gov/uscert/ncas/alerts.xml",
        "type": "rss",
        "priority": 10
    },
    {
        "name": "Microsoft Security Blog",
        "url": "https://www.microsoft.com/en-us/security/blog/feed/",
        "type": "rss",
        "priority": 8
    }
]


def setup_logging(log_dir: str = "logs", verbose: bool = False) -> logging.Logger:
    """
    Configure logging for the application.
    
    Args:
        log_dir: Directory to store log files
        verbose: Whether to enable debug logging
        
    Returns:
        Configured logger instance
    """
    level = logging.DEBUG if verbose else logging.INFO
    
    # Create logs directory if it doesn't exist
    os.makedirs(log_dir, exist_ok=True)
    
    # Include timestamp in log filename
    log_filename = f"{log_dir}/threat_intel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("threat_intel")


class RateLimiter:
    """Rate limiter to prevent overloading websites."""
    
    def __init__(self, base_delay: float = 1.0):
        """
        Initialize the rate limiter.
        
        Args:
            base_delay: Base delay between requests in seconds
        """
        self.base_delay = base_delay
        self.last_request: Dict[str, float] = {}  # Domain -> timestamp
    
    def wait_if_needed(self, url: str) -> None:
        """
        Wait appropriate time since last request to this domain.
        
        Args:
            url: URL to check for rate limiting
        """
        domain = urlparse(url).netloc
        current_time = time.time()
        
        # Add some randomness to appear more human-like
        delay = self.base_delay + random.uniform(0, self.base_delay * 0.5)
        
        # Check if we need to wait
        if domain in self.last_request:
            elapsed = current_time - self.last_request[domain]
            if elapsed < delay:
                wait_time = delay - elapsed + random.uniform(0, 0.5)
                time.sleep(wait_time)
        
        # Update last request time
        self.last_request[domain] = time.time()


def get_random_user_agent() -> str:
    """
    Get a random user agent string.
    
    Returns:
        Random user agent string
    """
    return random.choice(USER_AGENTS)


def create_request_headers(user_agent: Optional[str] = None) -> Dict[str, str]:
    """
    Create request headers with a user agent.
    
    Args:
        user_agent: Optional user agent string, random if not provided
        
    Returns:
        Dictionary of request headers
    """
    if user_agent is None:
        user_agent = get_random_user_agent()
        
    return {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }