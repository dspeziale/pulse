"""
Configuration management module for Pulse Network Monitor
"""

import os
import yaml
from typing import Any, Dict, Optional
import logging

logger = logging.getLogger(__name__)


class Config:
    """Configuration manager for Pulse"""

    _instance = None
    _config_data = None

    def __new__(cls):
        """Singleton pattern"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize configuration"""
        if self._config_data is None:
            self.load_config()

    def load_config(self, config_path: str = None):
        """Load configuration from YAML file"""
        if config_path is None:
            # Try multiple paths
            possible_paths = [
                'config/config.yaml',
                'config.yaml',
                '../config/config.yaml',
                os.path.join(os.path.dirname(__file__), '../../config/config.yaml')
            ]

            for path in possible_paths:
                if os.path.exists(path):
                    config_path = path
                    break

        if config_path is None or not os.path.exists(config_path):
            logger.warning("Configuration file not found, using defaults")
            self._config_data = self._get_default_config()
            return

        try:
            with open(config_path, 'r') as f:
                self._config_data = yaml.safe_load(f)
            logger.info(f"Configuration loaded from {config_path}")
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            self._config_data = self._get_default_config()

    def _get_default_config(self) -> Dict:
        """Get default configuration"""
        return {
            'database': {'path': 'instance/pulse.sqlite'},
            'scanner': {
                'default_network': '192.168.1.0/24',
                'nmap': {
                    'discovery_options': '-sn -T4',
                    'deep_scan_options': '-sV -O -A --script=default,discovery -T4',
                    'quick_scan_options': '-F -sV -T4',
                    'full_scan_options': '-p- -sV -T4'
                },
                'intervals': {
                    'discovery': 300,
                    'quick_scan': 900,
                    'deep_scan': 3600
                },
                'workers': {
                    'max_workers': 4,
                    'timeout': 600
                }
            },
            'recognition': {
                'oui_detection': True,
                'os_fingerprinting': True
            },
            'oui': {
                'update_url': 'https://standards-oui.ieee.org/oui/oui.txt',
                'update_interval': 604800,
                'cache_file': 'data/oui.txt'
            },
            'alerts': {
                'enabled': True,
                'channels': {},
                'rules': {}
            },
            'api': {
                'host': '0.0.0.0',
                'port': 5000,
                'debug': False
            },
            'export': {
                'output_dir': 'exports',
                'formats': ['json', 'csv', 'html', 'xml']
            },
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'file': 'logs/pulse.log',
                'max_bytes': 10485760,
                'backup_count': 5
            },
            'scheduler': {
                'jobstore': 'sqlite',
                'jobstore_path': 'instance/jobs.sqlite',
                'coalesce': True,
                'max_instances': 1
            }
        }

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation
        Example: config.get('scanner.nmap.discovery_options')
        """
        if self._config_data is None:
            self.load_config()

        keys = key.split('.')
        value = self._config_data

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key: str, value: Any):
        """
        Set configuration value using dot notation
        """
        if self._config_data is None:
            self.load_config()

        keys = key.split('.')
        config = self._config_data

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value

    def get_all(self) -> Dict:
        """Get all configuration"""
        if self._config_data is None:
            self.load_config()
        return self._config_data

    def save(self, config_path: str = 'config/config.yaml'):
        """Save configuration to YAML file"""
        try:
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            with open(config_path, 'w') as f:
                yaml.dump(self._config_data, f, default_flow_style=False)
            logger.info(f"Configuration saved to {config_path}")
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")


# Singleton instance
_config_instance = None

def get_config() -> Config:
    """Get configuration singleton instance"""
    global _config_instance
    if _config_instance is None:
        _config_instance = Config()
    return _config_instance
