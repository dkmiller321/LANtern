#!/usr/bin/env python3
"""
Run script for LAN Monitor.

This script provides a convenient way to run the LAN Monitor application
with various options.
"""

import os
import sys
import argparse
import subprocess
from pathlib import Path

def main():
    """Run the LAN Monitor application."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Run LAN Monitor")
    parser.add_argument(
        "--scan-only",
        action="store_true",
        help="Run only the scanner test script"
    )
    parser.add_argument(
        "--web-only",
        action="store_true",
        help="Run only the web server"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Run with debug logging"
    )
    
    args = parser.parse_args()
    
    # Get the project root directory
    project_root = Path(__file__).parent
    
    # Set up environment
    env = os.environ.copy()
    if args.debug:
        # Set logging level to DEBUG
        env["PYTHONPATH"] = str(project_root)
        
        # Update config to use DEBUG logging
        config_path = project_root / "config" / "config.yaml"
        if config_path.exists():
            with open(config_path, "r") as f:
                config_content = f.read()
            
            # Replace logging level with DEBUG
            if "level: " in config_content:
                config_content = config_content.replace('level: "INFO"', 'level: "DEBUG"')
                with open(config_path, "w") as f:
                    f.write(config_content)
    
    # Run the appropriate script
    if args.scan_only:
        print("Running scanner test...")
        subprocess.run([sys.executable, str(project_root / "test_scanner.py")], env=env)
    elif args.web_only:
        print("Running web server only...")
        subprocess.run([sys.executable, str(project_root / "main.py"), "--web-only"], env=env)
    else:
        print("Running full LAN Monitor application...")
        subprocess.run([sys.executable, str(project_root / "main.py")], env=env)

if __name__ == "__main__":
    main()
