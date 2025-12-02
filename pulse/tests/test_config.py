"""Tests for configuration module"""

import pytest
import tempfile
import os

from pulse.utils.config import Config


@pytest.fixture
def temp_config():
    """Create temporary config file"""
    config_content = """
database:
  path: "test.db"

scanner:
  default_network: "10.0.0.0/24"
  workers:
    max_workers: 2
    timeout: 300

api:
  host: "127.0.0.1"
  port: 8000
  debug: true

alerts:
  enabled: false
"""

    fd, path = tempfile.mkstemp(suffix='.yaml')
    with os.fdopen(fd, 'w') as f:
        f.write(config_content)

    config = Config()
    config.load_config(path)

    yield config

    if os.path.exists(path):
        os.unlink(path)


def test_config_initialization():
    """Test config initialization"""
    config = Config()
    assert config is not None


def test_config_get_value(temp_config):
    """Test getting config values"""
    assert temp_config.get('database.path') == 'test.db'
    assert temp_config.get('scanner.default_network') == '10.0.0.0/24'
    assert temp_config.get('api.host') == '127.0.0.1'
    assert temp_config.get('api.port') == 8000


def test_config_get_nested_value(temp_config):
    """Test getting nested config values"""
    assert temp_config.get('scanner.workers.max_workers') == 2
    assert temp_config.get('scanner.workers.timeout') == 300


def test_config_get_with_default(temp_config):
    """Test getting config with default value"""
    assert temp_config.get('nonexistent.key', 'default') == 'default'
    assert temp_config.get('another.missing.key', 123) == 123


def test_config_set_value(temp_config):
    """Test setting config values"""
    temp_config.set('test.key', 'test_value')
    assert temp_config.get('test.key') == 'test_value'


def test_config_set_nested_value(temp_config):
    """Test setting nested config values"""
    temp_config.set('new.nested.key', 'nested_value')
    assert temp_config.get('new.nested.key') == 'nested_value'


def test_config_get_all(temp_config):
    """Test getting all configuration"""
    all_config = temp_config.get_all()
    assert isinstance(all_config, dict)
    assert 'database' in all_config
    assert 'scanner' in all_config
    assert 'api' in all_config


def test_config_boolean_values(temp_config):
    """Test boolean config values"""
    assert temp_config.get('api.debug') is True
    assert temp_config.get('alerts.enabled') is False


def test_config_default_values():
    """Test default config values"""
    config = Config()
    config._config_data = None
    config.load_config('nonexistent.yaml')

    # Should load defaults
    default_network = config.get('scanner.default_network')
    assert default_network == '192.168.1.0/24'
