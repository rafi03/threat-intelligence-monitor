#!/usr/bin/env python3
"""
Command-line interface for the Threat Intelligence Monitor.
"""

import argparse
import sys
import textwrap
from typing import List

from .monitor import ThreatIntelligenceMonitor


def main(args: List[str] = None) -> int:
    """
    Main function to handle command line arguments and execute the monitor.
    
    Args:
        args: Command line arguments (defaults to sys.argv if None)
        
    Returns:
        Exit code (0 for success, 1 for error)
    """
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Monitor - Track security news and advisories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          threat-intel update --days 3
          threat-intel search "ransomware" --days 10 --output results.json
          threat-intel trends --days 7 --limit 20
        """)
    )
    
    # Global options
    parser.add_argument("--db", default="threat_intel.db", help="Database file path")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between requests in seconds")
    parser.add_argument("--workers", type=int, default=3, help="Maximum number of concurrent workers")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    # Command modes
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Update command
    update_parser = subparsers.add_parser("update", help="Update feeds and store new articles")
    update_parser.add_argument("-d", "--days", type=int, default=1, help="Process articles from last N days")
    
    # Search command
    search_parser = subparsers.add_parser("search", help="Search for articles")
    search_parser.add_argument("query", nargs="?", help="Search query")
    search_parser.add_argument("-d", "--days", type=int, default=7, help="Search in last N days")
    search_parser.add_argument("-l", "--limit", type=int, default=20, help="Maximum number of results")
    search_parser.add_argument("-o", "--output", help="Output JSON file")
    search_parser.add_argument("-c", "--csv", help="Output CSV file")
    
    # Trends command
    trends_parser = subparsers.add_parser("trends", help="Show trending keywords")
    trends_parser.add_argument("-d", "--days", type=int, default=3, help="Look at articles from last N days")
    trends_parser.add_argument("-l", "--limit", type=int, default=15, help="Maximum number of keywords")
    
    # Parse arguments
    args = parser.parse_args(args)
    
    if not args.command:
        parser.print_help()
        return 0
    
    try:
        # Initialize the monitor
        monitor = ThreatIntelligenceMonitor(
            db_path=args.db,
            delay=args.delay,
            max_workers=args.workers,
            verbose=args.verbose
        )
        
        # Execute the appropriate command
        if args.command == "update":
            print(f"Updating feeds (looking back {args.days} days)...")
            stats = monitor.update_feeds(days_back=args.days)
            print(f"\nUpdate complete:")
            print(f"Feeds processed: {stats['feeds_processed']}")
            print(f"New articles: {stats['new_articles']}")
            print(f"Errors: {stats['errors']}")
        
        elif args.command == "search":
            query = args.query
            if query:
                print(f"Searching for '{query}' in the last {args.days} days...")
            else:
                print(f"Getting the latest articles from the last {args.days} days...")
            
            articles = monitor.search_articles(query=query, days=args.days, limit=args.limit)
            monitor.print_articles(articles)
            
            if args.output:
                monitor.export_to_json(articles, args.output)
            
            if args.csv:
                monitor.export_to_csv(articles, args.csv)
        
        elif args.command == "trends":
            print(f"Getting trending keywords from the last {args.days} days...")
            trends = monitor.get_trending_keywords(days=args.days, limit=args.limit)
            
            if trends:
                print("\n===== TRENDING SECURITY TOPICS =====")
                max_count = trends[0][1] if trends else 0  # Highest count for scaling
                
                for keyword, count in trends:
                    # Create a simple bar chart with Unicode block characters
                    bar_length = int((count / max_count) * 20) if max_count > 0 else 0
                    bar = "█" * bar_length
                    print(f"{keyword.ljust(20)} {str(count).rjust(3)} {bar}")
            else:
                print("No trending keywords found. Try updating feeds first.")
                
        return 0
    
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())