"""
Notification module for LAN Monitor.

This module provides functionality to send notifications when
devices join or leave the network.
"""

import logging
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional
import requests

from lan_monitor.config import config
from lan_monitor.models import Device
from lan_monitor.utils.mac_vendor import mac_vendor_lookup

# Configure logging
logger = logging.getLogger(__name__)


class Notifier:
    """
    Notification manager for LAN Monitor.
    
    This class provides methods to send notifications when devices
    join or leave the network.
    """
    
    def __init__(self):
        """Initialize the notifier."""
        # Get notification settings from config
        self.email_enabled = config.get("notifications", "email_enabled", False)
        self.webhook_enabled = config.get("notifications", "webhook_enabled", False)
        self.notify_on_join = config.get("notifications", "notify_on_join", True)
        self.notify_on_leave = config.get("notifications", "notify_on_leave", True)
        self.watched_devices = config.get("notifications", "watched_devices", [])
        
        # Email settings
        if self.email_enabled:
            self.smtp_server = config.get("notifications", "smtp_server", "")
            self.smtp_port = config.get("notifications", "smtp_port", 587)
            self.smtp_username = config.get("notifications", "smtp_username", "")
            self.smtp_password = config.get("notifications", "smtp_password", "")
            self.recipients = config.get("notifications", "recipients", "").split(",")
        
        # Webhook settings
        if self.webhook_enabled:
            self.webhook_url = config.get("notifications", "webhook_url", "")
    
    def notify_device_joined(self, device: Dict[str, str]) -> None:
        """
        Send notification when a device joins the network.
        
        Args:
            device: Dictionary containing device information
        """
        if not self.notify_on_join:
            return
        
        # Check if device is in watched devices list
        mac = device['mac_address']
        if self.watched_devices and mac not in self.watched_devices:
            return
        
        # Get device details
        ip = device.get('ip_address', 'Unknown')
        hostname = device.get('hostname', 'Unknown')
        vendor = device.get('vendor', mac_vendor_lookup.lookup(mac))
        
        # Create notification message
        subject = f"Device Joined: {hostname or vendor or mac}"
        message = f"""
        A device has joined the network:
        
        MAC Address: {mac}
        IP Address: {ip}
        Hostname: {hostname or 'Unknown'}
        Vendor: {vendor or 'Unknown'}
        """
        
        # Send notifications
        self._send_notification(subject, message, device)
    
    def notify_device_left(self, device: Dict[str, str]) -> None:
        """
        Send notification when a device leaves the network.
        
        Args:
            device: Dictionary containing device information
        """
        if not self.notify_on_leave:
            return
        
        # Check if device is in watched devices list
        mac = device['mac_address']
        if self.watched_devices and mac not in self.watched_devices:
            return
        
        # Get device details
        ip = device.get('ip_address', 'Unknown')
        hostname = device.get('hostname', 'Unknown')
        vendor = device.get('vendor', mac_vendor_lookup.lookup(mac))
        
        # Create notification message
        subject = f"Device Left: {hostname or vendor or mac}"
        message = f"""
        A device has left the network:
        
        MAC Address: {mac}
        IP Address: {ip}
        Hostname: {hostname or 'Unknown'}
        Vendor: {vendor or 'Unknown'}
        """
        
        # Send notifications
        self._send_notification(subject, message, device)
    
    def _send_notification(self, subject: str, message: str, device: Dict[str, str]) -> None:
        """
        Send notification using configured methods.
        
        Args:
            subject: Notification subject
            message: Notification message
            device: Dictionary containing device information
        """
        if self.email_enabled:
            self._send_email(subject, message)
        
        if self.webhook_enabled:
            self._send_webhook(subject, message, device)
    
    def _send_email(self, subject: str, message: str) -> bool:
        """
        Send email notification.
        
        Args:
            subject: Email subject
            message: Email message
            
        Returns:
            True if email was sent successfully, False otherwise
        """
        if not self.email_enabled:
            return False
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.smtp_username
            msg['To'] = ", ".join(self.recipients)
            msg['Subject'] = subject
            
            # Add message body
            msg.attach(MIMEText(message, 'plain'))
            
            # Connect to SMTP server
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.smtp_username, self.smtp_password)
            
            # Send email
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email notification sent: {subject}")
            return True
        
        except Exception as e:
            logger.error(f"Error sending email notification: {e}")
            return False
    
    def _send_webhook(self, subject: str, message: str, device: Dict[str, str]) -> bool:
        """
        Send webhook notification.
        
        Args:
            subject: Notification subject
            message: Notification message
            device: Dictionary containing device information
            
        Returns:
            True if webhook was sent successfully, False otherwise
        """
        if not self.webhook_enabled:
            return False
        
        try:
            # Create payload
            payload = {
                'subject': subject,
                'message': message,
                'device': device,
                'event_type': 'join' if 'Joined' in subject else 'leave'
            }
            
            # Send webhook
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Webhook notification sent: {subject}")
                return True
            else:
                logger.warning(f"Webhook returned non-200 status code: {response.status_code}")
                return False
        
        except Exception as e:
            logger.error(f"Error sending webhook notification: {e}")
            return False


# Create a global instance for easy importing
notifier = Notifier()
