"""
Network scanner module for LAN Monitor.

This module provides functionality to scan the local network
for devices using various methods.
"""

import re
import socket
import logging
import ipaddress
import subprocess
from typing import Dict, List, Optional, Tuple
import concurrent.futures
from datetime import datetime

import netifaces
import nmap
from scapy.all import ARP, Ether, srp

from lan_monitor.config import config

# Configure logging
logger = logging.getLogger(__name__)


class NetworkScanner:
    """
    Network scanner for LAN Monitor.
    
    This class provides methods to scan the local network for devices
    using various techniques.
    """
    
    def __init__(self):
        """Initialize the network scanner."""
        # Get network settings from config
        self.subnet = config.get("network", "subnet", "192.168.1.0/24")
        self.timeout = config.get("network", "scan_timeout", 10)
        self.threads = config.get("network", "scan_threads", 4)
        
        # Initialize nmap scanner if available
        self.nm = None
        try:
            self.nm = nmap.PortScanner()
        except nmap.nmap.PortScannerError:
            logger.warning("nmap not found in system path. nmap scanning will be disabled.")
    
    def scan_network(self) -> List[Dict[str, str]]:
        """
        Scan the network for devices.
        
        Returns:
            List of dictionaries containing device information
        """
        logger.info(f"Starting network scan of {self.subnet}")
        start_time = datetime.now()
        
        # Try different scan methods and combine results
        arp_results = self._scan_arp()
        nmap_results = self._scan_nmap()
        ping_results = self._scan_ping()
        
        # Combine results, preferring nmap results for duplicates
        combined_results = self._combine_scan_results(arp_results, nmap_results)
        # Add ping results
        combined_results = self._combine_scan_results(combined_results, ping_results)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        logger.info(f"Network scan completed in {duration:.2f} seconds, found {len(combined_results)} devices")
        
        return combined_results
    
    def _scan_arp(self) -> List[Dict[str, str]]:
        """
        Scan the network using ARP requests.
        
        Returns:
            List of dictionaries containing device information
        """
        try:
            logger.debug(f"Starting ARP scan of {self.subnet}")
            
            # Create ARP request packet
            arp = ARP(pdst=self.subnet)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Send packet and get response
            result = srp(packet, timeout=self.timeout, verbose=0)[0]
            
            # Process results
            devices = []
            for sent, received in result:
                devices.append({
                    'mac_address': received.hwsrc.upper(),
                    'ip_address': received.psrc
                })
            
            logger.debug(f"ARP scan found {len(devices)} devices")
            return devices
        
        except Exception as e:
            logger.error(f"Error during ARP scan: {e}")
            return []
    
    def _scan_nmap(self) -> List[Dict[str, str]]:
        """
        Scan the network using nmap.
        
        Returns:
            List of dictionaries containing device information
        """
        # Skip if nmap is not available
        if self.nm is None:
            logger.debug("Skipping nmap scan as nmap is not available")
            return []
            
        try:
            logger.debug(f"Starting nmap scan of {self.subnet}")
            
            # Run nmap scan with more aggressive options for better device discovery
            # Use -n to skip DNS resolution which can speed up the scan
            # Use --system-dns to use system DNS instead of nmap's internal DNS
            self.nm.scan(hosts=self.subnet, arguments=f"-sn -T4 -n --system-dns --max-retries 2 --host-timeout {self.timeout}s")
            
            # Process results
            devices = []
            for host in self.nm.all_hosts():
                # Create a device entry even if MAC is not available
                device_info = {
                    'ip_address': host
                }
                
                # Add MAC address if available
                if 'addresses' in self.nm[host] and 'mac' in self.nm[host]['addresses']:
                    device_info['mac_address'] = self.nm[host]['addresses']['mac'].upper()
                else:
                    # Try to get MAC from ARP table if not provided by nmap
                    mac = self._get_mac_from_ip(host)
                    if mac:
                        device_info['mac_address'] = mac.upper()
                    else:
                        # Skip devices without MAC address as they can't be tracked properly
                        logger.debug(f"Skipping device {host} - no MAC address found")
                        continue
                
                # Add hostname if available
                if 'hostnames' in self.nm[host] and self.nm[host]['hostnames']:
                    for hostname in self.nm[host]['hostnames']:
                        if hostname['name'] and hostname['name'] != host:
                            device_info['hostname'] = hostname['name']
                            break
                
                devices.append(device_info)
            
            logger.debug(f"nmap scan found {len(devices)} devices")
            return devices
        
        except Exception as e:
            logger.error(f"Error during nmap scan: {e}", exc_info=True)
            return []
    
    def _scan_ping(self) -> List[Dict[str, str]]:
        """
        Scan the network using ping.
        
        Returns:
            List of dictionaries containing device information
        """
        try:
            logger.debug(f"Starting ping scan of {self.subnet}")
            
            # Get list of IP addresses to scan
            network = ipaddress.ip_network(self.subnet)
            ip_list = [str(ip) for ip in network.hosts()]
            
            # Ping hosts in parallel
            devices = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_ip = {executor.submit(self._ping_host, ip): ip for ip in ip_list}
                for future in concurrent.futures.as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        result = future.result()
                        if result:
                            devices.append(result)
                    except Exception as e:
                        logger.error(f"Error pinging {ip}: {e}")
            
            logger.debug(f"Ping scan found {len(devices)} devices")
            return devices
        
        except Exception as e:
            logger.error(f"Error during ping scan: {e}")
            return []
    
    def _ping_host(self, ip: str) -> Optional[Dict[str, str]]:
        """
        Ping a host and get its MAC address if reachable.
        
        Args:
            ip: IP address to ping
            
        Returns:
            Dictionary containing device information or None if unreachable
        """
        import platform
        
        # Determine ping command based on platform
        if platform.system().lower() == "windows":
            # Windows ping command
            ping_cmd = ['ping', '-n', '1', '-w', '1000', ip]
        else:
            # Linux/Mac ping command
            ping_cmd = ['ping', '-c', '1', '-W', '1', ip]
            
        try:
            if subprocess.call(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
                # Host is up, get MAC address from ARP table
                mac = self._get_mac_from_ip(ip)
                if mac:
                    return {
                        'mac_address': mac.upper(),
                        'ip_address': ip
                    }
        except Exception as e:
            logger.debug(f"Error pinging {ip}: {e}")
            
        return None
    
    def _get_mac_from_ip(self, ip: str) -> Optional[str]:
        """
        Get MAC address for an IP address from the ARP table.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            MAC address or None if not found
        """
        import platform
        
        try:
            # Determine arp command based on platform
            if platform.system().lower() == "windows":
                # Windows arp command
                output = subprocess.check_output(['arp', '-a', ip]).decode('utf-8')
            else:
                # Linux/Mac arp command
                output = subprocess.check_output(['arp', '-n', ip]).decode('utf-8')
            
            # Parse output
            for line in output.split('\n'):
                if ip in line:
                    mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                    if mac_match:
                        return mac_match.group(0)
        
        except Exception as e:
            logger.debug(f"Error getting MAC for {ip}: {e}")
        
        return None
    
    def _combine_scan_results(self, arp_results: List[Dict[str, str]], 
                             nmap_results: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Combine results from different scan methods.
        
        Args:
            arp_results: Results from ARP scan
            nmap_results: Results from nmap scan
            
        Returns:
            Combined list of device information
        """
        # Create a dictionary to store combined results
        combined = {}
        
        # Add ARP results
        for device in arp_results:
            mac = device['mac_address']
            combined[mac] = device
        
        # Add or update with nmap results
        for device in nmap_results:
            mac = device['mac_address']
            if mac in combined:
                # Update existing entry with additional information
                if 'hostname' in device and 'hostname' not in combined[mac]:
                    combined[mac]['hostname'] = device['hostname']
            else:
                # Add new entry
                combined[mac] = device
        
        # Convert back to list
        return list(combined.values())
    
    def get_local_network_info(self) -> Dict[str, str]:
        """
        Get information about the local network.
        
        Returns:
            Dictionary containing network information
        """
        try:
            # Get default gateway
            gateways = netifaces.gateways()
            
            # Check if default gateway exists
            if 'default' not in gateways or netifaces.AF_INET not in gateways['default']:
                logger.warning("No default gateway found, trying to find any available interface")
                # Try to find any interface with an IPv4 address
                for interface in netifaces.interfaces():
                    if netifaces.AF_INET in netifaces.ifaddresses(interface):
                        addresses = netifaces.ifaddresses(interface)
                        ip_info = addresses[netifaces.AF_INET][0]
                        local_ip = ip_info.get('addr', 'unknown')
                        netmask = ip_info.get('netmask', '255.255.255.0')
                        
                        # Use a placeholder for gateway
                        gateway = "unknown"
                        
                        # Calculate network address and CIDR if possible
                        try:
                            ip_obj = ipaddress.IPv4Address(local_ip)
                            mask_obj = ipaddress.IPv4Address(netmask)
                            network_addr = ipaddress.IPv4Address(int(ip_obj) & int(mask_obj))
                            cidr = bin(int(mask_obj)).count('1')
                            network = f"{network_addr}/{cidr}"
                        except:
                            network = self.subnet
                        
                        logger.info(f"Using interface {interface} with IP {local_ip}")
                        return {
                            'interface': interface,
                            'local_ip': local_ip,
                            'netmask': netmask,
                            'gateway': gateway,
                            'network': network
                        }
                
                # If we get here, no suitable interface was found
                raise ValueError("No suitable network interface found")
            
            # Normal path - default gateway exists
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            interface = gateways['default'][netifaces.AF_INET][1]
            
            # Get interface addresses
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET not in addresses or not addresses[netifaces.AF_INET]:
                raise ValueError(f"No IPv4 address found for interface {interface}")
                
            ip_info = addresses[netifaces.AF_INET][0]
            
            local_ip = ip_info.get('addr', 'unknown')
            netmask = ip_info.get('netmask', '255.255.255.0')
            
            # Calculate network address and CIDR
            ip_obj = ipaddress.IPv4Address(local_ip)
            mask_obj = ipaddress.IPv4Address(netmask)
            network_addr = ipaddress.IPv4Address(int(ip_obj) & int(mask_obj))
            
            # Count bits in netmask
            cidr = bin(int(mask_obj)).count('1')
            
            logger.info(f"Network info: interface={interface}, ip={local_ip}, gateway={default_gateway}")
            return {
                'interface': interface,
                'local_ip': local_ip,
                'netmask': netmask,
                'gateway': default_gateway,
                'network': f"{network_addr}/{cidr}"
            }
        
        except Exception as e:
            logger.error(f"Error getting network info: {e}")
            # Return a more informative error message
            return {
                'interface': 'unknown',
                'local_ip': 'unknown',
                'netmask': 'unknown',
                'gateway': 'unknown',
                'network': self.subnet,
                'error': str(e)
            }


# Create a global instance for easy importing
network_scanner = NetworkScanner()
