"""
MAC vendor lookup utility.

This module provides functionality to lookup vendor information
based on MAC addresses.
"""

import re
import json
import logging
import requests
from pathlib import Path
from typing import Dict, Optional
from mac_vendor_lookup import MacLookup, BaseMacLookup

# Configure logging
logger = logging.getLogger(__name__)


class MacVendorLookup:
    """MAC address vendor lookup utility."""

    def __init__(self, cache_file: Optional[str] = None):
        """
        Initialize the MAC vendor lookup utility.

        Args:
            cache_file: Path to the cache file. If None, uses default path.
        """
        self.mac_lookup = MacLookup()
        
        # Set cache file path
        if cache_file is None:
            # Get the project root directory (3 levels up from this file)
            root_dir = Path(__file__).parent.parent.parent
            cache_file = root_dir / "data" / "mac_vendors.json"
        
        self.cache_file = Path(cache_file)
        self.vendor_cache = self._load_cache()
        
        # Update the cache if needed
        try:
            self.mac_lookup.update_vendors()
        except Exception as e:
            logger.warning(f"Failed to update MAC vendors: {e}")

    def _load_cache(self) -> Dict[str, str]:
        """
        Load the vendor cache from file.

        Returns:
            Dictionary mapping MAC prefixes to vendor names
        """
        if not self.cache_file.exists():
            return {}
        
        try:
            with open(self.cache_file, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading MAC vendor cache: {e}")
            return {}

    def _save_cache(self) -> None:
        """Save the vendor cache to file."""
        try:
            # Ensure the directory exists
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.cache_file, "w") as f:
                json.dump(self.vendor_cache, f, indent=2)
        except IOError as e:
            logger.error(f"Error saving MAC vendor cache: {e}")

    def normalize_mac(self, mac: str) -> str:
        """
        Normalize MAC address format.

        Args:
            mac: MAC address in any format

        Returns:
            Normalized MAC address (uppercase, colon-separated)
        """
        # Remove all non-hexadecimal characters
        mac = re.sub(r'[^0-9A-Fa-f]', '', mac)
        
        # Format as colon-separated pairs
        mac = ':'.join(mac[i:i+2] for i in range(0, len(mac), 2))
        
        return mac.upper()

    def lookup(self, mac: str) -> str:
        """
        Lookup vendor information for a MAC address.

        Args:
            mac: MAC address to lookup

        Returns:
            Vendor name or "Unknown" if not found
        """
        try:
            # Normalize the MAC address
            normalized_mac = self.normalize_mac(mac)
            
            # Check the cache first
            if normalized_mac in self.vendor_cache:
                return self.vendor_cache[normalized_mac]
            
            # Try to lookup using the library
            vendor = self.mac_lookup.lookup(normalized_mac)
            
            # Cache the result
            self.vendor_cache[normalized_mac] = vendor
            self._save_cache()
            
            return vendor
        except (KeyError, BaseMacLookup.NotFoundError):
            # Try to lookup using the API
            return self._lookup_api(normalized_mac)
        except Exception as e:
            logger.error(f"Error looking up MAC vendor: {e}")
            return "Unknown"

    def _lookup_api(self, mac: str) -> str:
        """
        Lookup vendor information using an API.

        Args:
            mac: Normalized MAC address

        Returns:
            Vendor name or "Unknown" if not found
        """
        try:
            # Use the macvendors.com API
            url = f"https://api.macvendors.com/{mac}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                vendor = response.text
                # Cache the result
                self.vendor_cache[mac] = vendor
                self._save_cache()
                return vendor
            
            return "Unknown"
        except Exception as e:
            logger.error(f"Error looking up MAC vendor via API: {e}")
            return "Unknown"


# Create a global instance for easy importing
mac_vendor_lookup = MacVendorLookup()
