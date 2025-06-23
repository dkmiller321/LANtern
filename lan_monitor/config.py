"""
Configuration module for LAN Monitor.

This module provides functionality to load and access configuration
settings from the YAML configuration file.
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional


class Config:
    """Configuration manager for LAN Monitor."""

    _instance = None
    _config_data = None

    def __new__(cls, config_path: Optional[str] = None):
        """Implement singleton pattern for Config class."""
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
            cls._instance._load_config(config_path)
        return cls._instance

    def _load_config(self, config_path: Optional[str] = None) -> None:
        """
        Load configuration from YAML file.

        Args:
            config_path: Path to the configuration file. If None, uses default path.
        """
        if config_path is None:
            # Get the project root directory (2 levels up from this file)
            root_dir = Path(__file__).parent.parent
            config_path = os.path.join(root_dir, "config", "config.yaml")

        try:
            with open(config_path, "r") as f:
                self._config_data = yaml.safe_load(f)
        except FileNotFoundError:
            print(f"Configuration file not found: {config_path}")
            self._config_data = {}
        except yaml.YAMLError as e:
            print(f"Error parsing configuration file: {e}")
            self._config_data = {}

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """
        Get a configuration value.

        Args:
            section: Configuration section name
            key: Configuration key name
            default: Default value if key is not found

        Returns:
            The configuration value or default if not found
        """
        if not self._config_data or section not in self._config_data:
            return default
        
        section_data = self._config_data.get(section, {})
        return section_data.get(key, default)

    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Get an entire configuration section.

        Args:
            section: Configuration section name

        Returns:
            Dictionary containing the section data or empty dict if not found
        """
        if not self._config_data:
            return {}
        
        return self._config_data.get(section, {})

    def reload(self, config_path: Optional[str] = None) -> None:
        """
        Reload configuration from file.

        Args:
            config_path: Path to the configuration file. If None, uses the last path.
        """
        self._load_config(config_path)


# Create a global instance for easy importing
config = Config()
