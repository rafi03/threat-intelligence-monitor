# Threat Intelligence Monitor
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/github/license/rafi03/threat-intelligence-monitor)
![Tests](https://github.com/rafi03/threat-intelligence-monitor/actions/workflows/python-tests.yml/badge.svg)


A Python tool for monitoring security blogs and feeds to gather the latest information about cyber threats, vulnerabilities, and security advisories.

## Table of Contents

- [Threat Intelligence Monitor](#threat-intelligence-monitor)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Features](#features)
  - [Documentation](#documentation)
  - [Installation](#installation)
    - [Using Conda (Recommended)](#using-conda-recommended)
    - [Using pip](#using-pip)
  - [Usage](#usage)
    - [Updating Feeds](#updating-feeds)
    - [Searching for Articles](#searching-for-articles)
    - [Viewing Trending Topics](#viewing-trending-topics)
    - [Exporting Data](#exporting-data)
  - [Architecture](#architecture)
    - [Module Structure](#module-structure)
    - [Key Components](#key-components)
  - [Security Feeds](#security-feeds)
  - [Development](#development)
    - [Running Tests](#running-tests)
    - [Adding New Features](#adding-new-features)
  - [Use Cases](#use-cases)
    - [Security Operations Analyst](#security-operations-analyst)
    - [Penetration Tester](#penetration-tester)
    - [Security Researcher](#security-researcher)
  - [Future Enhancements](#future-enhancements)
  - [License](#license)

## Overview

Staying up-to-date with the latest security threats and vulnerabilities is essential for cybersecurity professionals. The Threat Intelligence Monitor automates the collection and analysis of security information from reputable sources, allowing security teams to:

- Collect the latest security advisories, vulnerabilities, and threat information
- Search across multiple security feeds with a unified interface
- Identify trending security topics and potential emerging threats
- Export findings for integration with other security tools and reports

This tool serves as both a practical utility for security professionals and a demonstration of Python skills for cybersecurity roles.

## Features

- **Multi-source monitoring**: Aggregates information from leading security blogs and advisory sources
- **Intelligent content extraction**: Extracts relevant content from articles while filtering out noise
- **Keyword analysis**: Identifies important security terms, CVEs, and trending topics
- **Flexible search**: Find relevant articles across all monitored sources
- **Data export**: Export findings to JSON or CSV for further analysis or reporting
- **Trend analysis**: Identify emerging security threats based on keyword frequency
- **Rate limiting**: Respectful crawling with built-in delays to avoid overloading sources
- **Persistent storage**: SQLite database for efficient storage and retrieval

## Documentation

- [Quick Start Guide](#usage)
- [Detailed Code Documentation](CODE_EXPLANATION.md) - In-depth explanation of how the code works
- [API Reference](#architecture)

## Installation

### Using Conda (Recommended)

```bash
# Clone the repository
git clone https://github.com/rafi03/threat-intelligence-monitor.git
cd threat-intelligence-monitor

# Create a conda environment
conda create -n threat-intel python=3.10
conda activate threat-intel

# Install dependencies
pip install -e .
```

### Using pip

```bash
# Clone the repository
git clone https://github.com/rafi03/threat-intelligence-monitor.git
cd threat-intelligence-monitor

# Install the package
pip install -e .
```

## Usage

### Updating Feeds

Before searching or analyzing trends, you need to update the local database with the latest articles:

```bash
# Update with articles from the last day (default)
threat-intel update

# Update with articles from the last 3 days
threat-intel update --days 3
```

### Searching for Articles

Search for specific security topics across all monitored sources:

```bash
# Search for articles about ransomware
threat-intel search "ransomware"

# Search for a specific CVE
threat-intel search "CVE-2023-1234"

# Search with a longer timeframe (last 14 days)
threat-intel search "zero-day" --days 14

# Limit the number of results
threat-intel search "malware" --limit 5
```

### Viewing Trending Topics

Identify trending security topics based on keyword frequency:

```bash
# View trending topics from the last 3 days (default)
threat-intel trends

# View more trending topics 
threat-intel trends --limit 20

# View trending topics from the last week
threat-intel trends --days 7
```

### Exporting Data

Export search results for reporting or further analysis:

```bash
# Export search results to JSON
threat-intel search "supply chain" --output results.json

# Export search results to CSV
threat-intel search "phishing" --csv results.csv

# Export to both formats
threat-intel search "ransomware" --output results.json --csv results.csv
```

## Architecture

### Module Structure

The package follows a modular design with clear separation of concerns:

```
threat_intel/
├── __init__.py      # Package initialization
├── cli.py           # Command-line interface
├── content.py       # Content extraction and processing
├── database.py      # Database operations
├── monitor.py       # Main monitoring functionality
└── utils.py         # Utility functions and classes
```

### Key Components

- **ThreatIntelligenceMonitor**: Core class orchestrating the monitoring process
- **ContentExtractor**: Handles parsing feeds and extracting content from articles
- **ThreatDatabase**: Manages database operations for storing and retrieving articles
- **RateLimiter**: Ensures respectful crawling by limiting request frequency

## Security Feeds

The tool monitors these high-quality security information sources by default:

- **Krebs on Security**: In-depth security news and investigation
- **Schneier on Security**: Security analysis from a leading expert
- **US-CERT Advisories**: Official government security advisories
- **Microsoft Security Blog**: Updates from Microsoft's security team

Additional feeds can be added by modifying the `DEFAULT_SECURITY_FEEDS` list in `utils.py`.

## Development

### Running Tests

```bash
# Install development dependencies
pip install pytest

# Run tests
python -m pytest

# Run tests with verbose output
python -m pytest -v
```

### Adding New Features

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Implement your changes
4. Add tests for your changes
5. Run the tests (`python -m pytest`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## Use Cases

### Security Operations Analyst
- Monitor for new vulnerabilities affecting your organization's technology stack
- Set up daily scans for emerging threats to include in security briefings
- Export findings to integrate with ticketing or threat management systems

### Penetration Tester
- Stay current on the latest vulnerability disclosures
- Research exploitation techniques being discussed in security circles
- Gather intelligence on evolving attack vectors

### Security Researcher
- Track trends in the security landscape over time
- Collect data for research papers or security analysis
- Identify patterns in vulnerability disclosures

## Future Enhancements

- Add MITRE ATT&CK framework mapping for identified threats
- Implement machine learning for more accurate article relevance scoring
- Create a web interface for easier interaction
- Add notification capabilities for critical vulnerabilities
- Integrate with threat intelligence platforms via APIs

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

*This tool is intended for legitimate security research and monitoring. Always respect website terms of service and robots.txt files when collecting data.*