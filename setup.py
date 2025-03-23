#!/usr/bin/env python3
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="threat-intel-monitor",
    version="0.1.0",
    author="Abdullah Al Rafi",
    author_email="alrafikp@gmail.com",
    description="A tool for monitoring security blogs and feeds for threat intelligence",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rafi03/threat-intelligence-monitor",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=[
        "feedparser",
        "requests",
        "beautifulsoup4",
    ],
    entry_points={
        "console_scripts": [
            "threat-intel=threat_intel.cli:main",
        ],
    },
)