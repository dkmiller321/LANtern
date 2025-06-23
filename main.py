#!/usr/bin/env python3
"""
LAN Monitor - Main entry point.

This script starts the LAN Monitor application, including the
background scanner service and web dashboard.
"""

import os
import sys
import time
import logging
import argparse
import threading
import signal
import schedule
from pathlib import Path

import uvicorn
from fastapi import FastAPI

from lan_monitor.config import config
from lan_monitor.scanner import network_scanner
from lan_monitor.tracker import device_tracker
from lan_monitor.notifier import notifier
from lan_monitor.web.app import app as web_app

# Configure logging
logger = logging.getLogger(__name__)

def setup_logging():
    """Set up logging configuration."""
    log_level = config.get("logging", "level", "INFO")
    log_file = config.get("logging", "file", "logs/lan_monitor.log")
    
    # Create logs directory if it doesn't exist
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )


# Scanner service
class ScannerService:
    """Background scanner service for LAN Monitor."""
    
    def __init__(self):
        """Initialize the scanner service."""
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.scan_interval = config.get("network", "scan_interval", 300)
        
        # Schedule regular scans
        schedule.every(self.scan_interval).seconds.do(self.scan_network)
    
    def scan_network(self):
        """Scan the network and update device status."""
        try:
            self.logger.info("Starting network scan")
            
            # Scan network
            devices = network_scanner.scan_network()
            
            # Log all found devices for debugging
            for device in devices:
                mac = device.get('mac_address', 'Unknown MAC')
                ip = device.get('ip_address', 'Unknown IP')
                hostname = device.get('hostname', 'Unknown hostname')
                self.logger.debug(f"Found device: MAC={mac}, IP={ip}, Hostname={hostname}")
            
            # Update device status
            joined_devices, left_devices = device_tracker.update_devices(devices)
            
            # Send notifications for joined devices
            for mac in joined_devices:
                device = device_tracker.get_device_details(mac)
                if device:
                    notifier.notify_device_joined(device)
                    self.logger.info(f"Device joined: {mac} ({device.get('ip_address', 'Unknown IP')})")
            
            # Send notifications for left devices
            for mac in left_devices:
                device = device_tracker.get_device_details(mac)
                if device:
                    notifier.notify_device_left(device)
                    self.logger.info(f"Device left: {mac} ({device.get('ip_address', 'Unknown IP')})")
            
            self.logger.info(f"Network scan completed, found {len(devices)} devices")
            return True
        
        except Exception as e:
            self.logger.error(f"Error during network scan: {e}", exc_info=True)
            return False
    
    def start(self):
        """Start the scanner service."""
        self.running = True
        self.logger.info("Starting scanner service")
        
        # Run initial scan
        self.scan_network()
        
        # Start scheduler thread
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop)
        self.scheduler_thread.daemon = True
        self.scheduler_thread.start()
    
    def stop(self):
        """Stop the scanner service."""
        self.running = False
        self.logger.info("Stopping scanner service")
    
    def _scheduler_loop(self):
        """Run the scheduler loop."""
        while self.running:
            schedule.run_pending()
            time.sleep(1)


# Web server
class WebServer:
    """Web server for LAN Monitor."""
    
    def __init__(self):
        """Initialize the web server."""
        self.logger = logging.getLogger(__name__)
        self.host = config.get("web", "host", "0.0.0.0")
        self.port = config.get("web", "port", 8000)
        self.app = web_app
    
    def start(self):
        """Start the web server."""
        self.logger.info(f"Starting web server on {self.host}:{self.port}")
        
        # Run the web server
        uvicorn.run(
            self.app,
            host=self.host,
            port=self.port,
            log_level="info"
        )


# Main application
class LanMonitor:
    """Main LAN Monitor application."""
    
    def __init__(self):
        """Initialize the LAN Monitor application."""
        self.logger = logging.getLogger(__name__)
        self.scanner_service = ScannerService()
        self.web_server = WebServer()
    
    def start(self):
        """Start the LAN Monitor application."""
        self.logger.info("Starting LAN Monitor")
        
        # Start scanner service
        self.scanner_service.start()
        
        # Start web server (this will block)
        self.web_server.start()
    
    def stop(self):
        """Stop the LAN Monitor application."""
        self.logger.info("Stopping LAN Monitor")
        
        # Stop scanner service
        self.scanner_service.stop()


# Signal handler
def signal_handler(sig, frame):
    """Handle signals to gracefully shut down."""
    logging.info("Shutting down LAN Monitor")
    sys.exit(0)


# Command line arguments
def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="LAN Monitor")
    parser.add_argument(
        "--config",
        help="Path to configuration file",
        default=None
    )
    parser.add_argument(
        "--scan-now",
        action="store_true",
        help="Perform a network scan and exit"
    )
    parser.add_argument(
        "--web-only",
        action="store_true",
        help="Run only the web server, not the scanner service"
    )
    parser.add_argument(
        "--scanner-only",
        action="store_true",
        help="Run only the scanner service, not the web server"
    )
    
    return parser.parse_args()


# Main entry point
def main():
    """Main entry point."""
    # Parse command line arguments
    args = parse_args()
    
    # Set up logging
    setup_logging()
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Load configuration
    if args.config:
        config.reload(args.config)
    
    # Run in scan-now mode
    if args.scan_now:
        scanner = ScannerService()
        scanner.scan_network()
        return
    
    # Run in web-only mode
    if args.web_only:
        # Load sample data for demonstration
        logger.info("Running in web-only mode with sample data")
        try:
            # Initialize the tracker with sample data
            device_tracker.load_sample_data()
            logger.info("Sample data loaded successfully")
        except Exception as e:
            logger.error(f"Error loading sample data: {e}")
        
        # Start web server
        web_server = WebServer()
        web_server.start()
        return
    
    # Run in scanner-only mode
    if args.scanner_only:
        scanner = ScannerService()
        scanner.start()
        
        # Keep the main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            scanner.stop()
        
        return
    
    # Run full application
    app = LanMonitor()
    app.start()


if __name__ == "__main__":
    main()
