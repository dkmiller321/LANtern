"""
Device tracker module for LAN Monitor.

This module provides functionality to track devices on the network
and record their presence in the database.
"""

import logging
import datetime
from typing import Dict, List, Optional, Tuple

from lan_monitor.models import db, Device, DeviceHistory
from lan_monitor.utils.mac_vendor import mac_vendor_lookup

# Configure logging
logger = logging.getLogger(__name__)


class DeviceTracker:
    """
    Device tracker for LAN Monitor.
    
    This class tracks devices on the network and records their presence
    in the database.
    """
    
    def __init__(self):
        """Initialize the device tracker."""
        self.db = db
    
    def update_devices(self, devices: List[Dict[str, str]]) -> Tuple[List[str], List[str]]:
        """
        Update device status in the database.
        
        Args:
            devices: List of dictionaries containing device information
                    Each dictionary should have 'mac_address' and 'ip_address' keys
                    Optionally can include 'hostname' key
        
        Returns:
            Tuple of (joined_devices, left_devices) MAC addresses
        """
        # Get current online devices from database
        with self.db.get_session() as session:
            db_devices = session.query(Device).filter(Device.is_online == True).all()
            db_mac_addresses = {device.mac_address for device in db_devices}
            
            # Get MAC addresses from current scan
            current_mac_addresses = {device['mac_address'] for device in devices}
            
            # Determine which devices joined and left
            joined_macs = current_mac_addresses - db_mac_addresses
            left_macs = db_mac_addresses - current_mac_addresses
            
            # Process joined devices
            joined_devices = []
            for device_info in devices:
                mac = device_info['mac_address']
                if mac in joined_macs:
                    joined_devices.append(mac)
                    self._process_joined_device(session, device_info)
                else:
                    # Update existing device
                    self._update_existing_device(session, device_info)
            
            # Process left devices
            left_devices = []
            for mac in left_macs:
                left_devices.append(mac)
                self._process_left_device(session, mac)
            
            # Commit all changes
            session.commit()
            
            return joined_devices, left_devices
    
    def _process_joined_device(self, session, device_info: Dict[str, str]) -> None:
        """
        Process a device that joined the network.
        
        Args:
            session: Database session
            device_info: Dictionary containing device information
        """
        mac = device_info['mac_address']
        ip = device_info.get('ip_address', '')
        hostname = device_info.get('hostname', '')
        
        # Look up vendor information
        try:
            vendor = mac_vendor_lookup.lookup(mac)
        except Exception as e:
            logger.debug(f"Error looking up vendor for {mac}: {e}")
            vendor = "Unknown"
        
        # Check if device exists in database
        device = session.query(Device).filter(Device.mac_address == mac).first()
        
        if device:
            # Update existing device
            device.ip_address = ip
            if hostname and hostname != device.hostname:
                device.hostname = hostname
            device.last_seen = datetime.datetime.utcnow()
            device.is_online = True
            
            logger.info(f"Device rejoined: {mac} ({ip})")
        else:
            # Create new device
            device = Device(
                mac_address=mac,
                ip_address=ip,
                hostname=hostname,
                vendor=vendor,
                is_online=True
            )
            session.add(device)
            
            logger.info(f"New device joined: {mac} ({ip})")
        
        # Add history entry
        history = DeviceHistory(
            device=device,
            event_type="join",
            ip_address=ip
        )
        session.add(history)
    
    def _update_existing_device(self, session, device_info: Dict[str, str]) -> None:
        """
        Update an existing device.
        
        Args:
            session: Database session
            device_info: Dictionary containing device information
        """
        mac = device_info['mac_address']
        ip = device_info.get('ip_address', '')
        hostname = device_info.get('hostname', '')
        
        # Update device information
        device = session.query(Device).filter(Device.mac_address == mac).first()
        if device:
            # Only update if IP or hostname changed
            if device.ip_address != ip or (hostname and device.hostname != hostname):
                device.ip_address = ip
                if hostname:
                    device.hostname = hostname
                device.last_seen = datetime.datetime.utcnow()
                
                logger.debug(f"Updated device: {mac} ({ip})")
            else:
                # Just update last_seen
                device.last_seen = datetime.datetime.utcnow()
    
    def _process_left_device(self, session, mac_address: str) -> None:
        """
        Process a device that left the network.
        
        Args:
            session: Database session
            mac_address: MAC address of the device
        """
        # Update device status
        device = session.query(Device).filter(Device.mac_address == mac_address).first()
        if device:
            device.is_online = False
            
            # Add history entry
            history = DeviceHistory(
                device=device,
                event_type="leave",
                ip_address=device.ip_address
            )
            session.add(history)
            
            logger.info(f"Device left: {mac_address} ({device.ip_address})")
    
    def get_device_details(self, mac_address: str) -> Optional[Dict]:
        """
        Get detailed information about a device.
        
        Args:
            mac_address: MAC address of the device
            
        Returns:
            Dictionary containing device details or None if not found
        """
        device = self.db.get_device_by_mac(mac_address)
        if not device:
            return None
        
        # Get device history
        history = self.db.get_device_history(device.id)
        
        # Format history entries
        history_entries = []
        for entry in history:
            history_entries.append({
                'timestamp': entry.timestamp.isoformat(),
                'event_type': entry.event_type,
                'ip_address': entry.ip_address
            })
        
        # Build device details
        return {
            'id': device.id,
            'mac_address': device.mac_address,
            'ip_address': device.ip_address,
            'hostname': device.hostname,
            'vendor': device.vendor,
            'first_seen': device.first_seen.isoformat(),
            'last_seen': device.last_seen.isoformat(),
            'is_online': device.is_online,
            'history': history_entries
        }
    
    def get_all_devices(self) -> List[Dict]:
        """
        Get information about all devices.
        
        Returns:
            List of dictionaries containing device information
        """
        devices = self.db.get_all_devices()
        
        # Format device information
        result = []
        for device in devices:
            result.append({
                'id': device.id,
                'mac_address': device.mac_address,
                'ip_address': device.ip_address,
                'hostname': device.hostname,
                'vendor': device.vendor,
                'first_seen': device.first_seen.isoformat(),
                'last_seen': device.last_seen.isoformat(),
                'is_online': device.is_online
            })
        
        return result
    
    def get_online_devices(self) -> List[Dict]:
        """
        Get information about online devices.
        
        Returns:
            List of dictionaries containing device information
        """
        devices = self.db.get_online_devices()
        
        # Format device information
        result = []
        for device in devices:
            result.append({
                'id': device.id,
                'mac_address': device.mac_address,
                'ip_address': device.ip_address,
                'hostname': device.hostname,
                'vendor': device.vendor,
                'first_seen': device.first_seen.isoformat(),
                'last_seen': device.last_seen.isoformat(),
                'is_online': device.is_online
            })
        
        return result


    def load_sample_data(self) -> None:
        """
        Load sample data from the devices.json file.
        
        This is used for demonstration purposes when running in web-only mode.
        """
        import os
        import json
        from datetime import datetime
        
        # Path to sample data file
        sample_data_path = os.path.join('data', 'devices.json')
        
        try:
            # Load sample data from file
            logger.info(f"Loading sample data from {sample_data_path}")
            with open(sample_data_path, 'r') as f:
                data = json.load(f)
            
            # Process devices
            with self.db.get_session() as session:
                # Clear existing devices
                session.query(Device).delete()
                session.query(DeviceHistory).delete()
                
                # Add sample devices
                for device_data in data.get('devices', []):
                    # Create device
                    device = Device(
                        mac_address=device_data['mac_address'],
                        ip_address=device_data['ip_address'],
                        hostname=device_data.get('hostname', ''),
                        vendor=device_data.get('vendor', 'Unknown'),
                        first_seen=datetime.fromisoformat(device_data['first_seen'].replace('Z', '+00:00')),
                        last_seen=datetime.fromisoformat(device_data['last_seen'].replace('Z', '+00:00')),
                        is_online=device_data['is_online']
                    )
                    session.add(device)
                    session.flush()  # Flush to get device ID
                    
                    # Add history entries
                    for history_entry in device_data.get('history', []):
                        history = DeviceHistory(
                            device_id=device.id,
                            timestamp=datetime.fromisoformat(history_entry['timestamp'].replace('Z', '+00:00')),
                            event_type=history_entry['event_type'],
                            ip_address=history_entry['ip_address']
                        )
                        session.add(history)
                
                # Commit changes
                session.commit()
                
            logger.info(f"Loaded {len(data.get('devices', []))} sample devices")
        
        except Exception as e:
            logger.error(f"Error loading sample data: {e}")
            raise


# Create a global instance for easy importing
device_tracker = DeviceTracker()
