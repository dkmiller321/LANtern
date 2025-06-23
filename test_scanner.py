#!/usr/bin/env python3
"""
Test script for LAN Monitor scanner.

This script runs the network scanner and prints the results.
"""

import sys
import logging
import json
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
)

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import scanner
from lan_monitor.scanner import network_scanner
from lan_monitor.tracker import device_tracker

def main():
    """Run the scanner and print results."""
    print("Starting network scan...")
    
    # Run the scan
    devices = network_scanner.scan_network()
    
    # Print results
    print(f"\nFound {len(devices)} devices:")
    for i, device in enumerate(devices, 1):
        mac = device.get('mac_address', 'Unknown MAC')
        ip = device.get('ip_address', 'Unknown IP')
        hostname = device.get('hostname', 'Unknown hostname')
        print(f"{i}. MAC: {mac}, IP: {ip}, Hostname: {hostname}")
    
    # Save results to a file
    output_file = project_root / "scan_results.json"
    with open(output_file, 'w') as f:
        json.dump(devices, f, indent=2)
    
    print(f"\nResults saved to {output_file}")
    
    # Update the database
    print("\nUpdating device database...")
    joined_devices, left_devices = device_tracker.update_devices(devices)
    
    print(f"Joined devices: {len(joined_devices)}")
    for mac in joined_devices:
        device = device_tracker.get_device_details(mac)
        if device:
            print(f"  - {mac} ({device.get('ip_address', 'Unknown IP')})")
    
    print(f"Left devices: {len(left_devices)}")
    for mac in left_devices:
        device = device_tracker.get_device_details(mac)
        if device:
            print(f"  - {mac} ({device.get('ip_address', 'Unknown IP')})")
    
    # Get all devices from the database
    all_devices = device_tracker.get_all_devices()
    print(f"\nTotal devices in database: {len(all_devices)}")
    
    # Get online devices from the database
    online_devices = device_tracker.get_online_devices()
    print(f"Online devices in database: {len(online_devices)}")
    
    print("\nDone!")

if __name__ == "__main__":
    main()
