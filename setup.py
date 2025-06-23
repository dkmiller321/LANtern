#!/usr/bin/env python3
"""
Setup script for LAN Monitor.
"""

import os
from setuptools import setup, find_packages

# Get the long description from the README file
with open(os.path.join(os.path.dirname(__file__), "README.md"), encoding="utf-8") as f:
    long_description = f.read()

# Get version from package
with open(os.path.join("lan_monitor", "__init__.py"), encoding="utf-8") as f:
    for line in f:
        if line.startswith("__version__"):
            version = line.split("=")[1].strip().strip('"\'')
            break

setup(
    name="lan-monitor",
    version=version,
    description="A network monitoring application that scans your local network, tracks device presence, and provides a web dashboard.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="LAN Monitor Team",
    author_email="example@example.com",
    url="https://github.com/example/lan-monitor",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "scapy>=2.5.0",
        "netifaces>=0.11.0",
        "python-nmap>=0.7.1",
        "fastapi>=0.95.1",
        "uvicorn>=0.22.0",
        "jinja2>=3.1.2",
        "python-multipart>=0.0.6",
        "sqlalchemy>=2.0.12",
        "alembic>=1.10.4",
        "aiosqlite>=0.19.0",
        "pyyaml>=6.0",
        "python-dotenv>=1.0.0",
        "schedule>=1.2.0",
        "mac-vendor-lookup>=0.1.12",
        "requests>=2.29.0",
    ],
    entry_points={
        "console_scripts": [
            "lan-monitor=lan_monitor.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.8",
)
