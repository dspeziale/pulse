"""Tests for device recognition module"""

import pytest
from pulse.services.device_recognition import DeviceRecognition
from pulse.utils.config import Config


@pytest.fixture
def recognition():
    """Create device recognition instance"""
    config = Config()
    return DeviceRecognition(config=config)


def test_recognition_initialization(recognition):
    """Test recognition initialization"""
    assert recognition is not None


def test_classify_router(recognition):
    """Test classifying router device"""
    device_data = {
        'hostname': 'router.local',
        'vendor': 'Cisco',
        'metadata': {
            'ports': [
                {'port': '22', 'state': 'open'},
                {'port': '23', 'state': 'open'},
                {'port': '80', 'state': 'open'},
            ]
        }
    }

    device_type = recognition.classify_device(device_data)
    assert device_type == 'router'


def test_classify_server(recognition):
    """Test classifying server device"""
    device_data = {
        'hostname': 'webserver',
        'os_name': 'Ubuntu Linux',
        'os_family': 'Linux',
        'metadata': {
            'ports': [
                {'port': '22', 'state': 'open'},
                {'port': '80', 'state': 'open'},
                {'port': '443', 'state': 'open'},
            ]
        }
    }

    device_type = recognition.classify_device(device_data)
    assert device_type == 'server'


def test_classify_printer(recognition):
    """Test classifying printer device"""
    device_data = {
        'hostname': 'printer-office',
        'vendor': 'HP',
        'metadata': {
            'ports': [
                {'port': '9100', 'state': 'open'},
                {'port': '631', 'state': 'open'},
            ]
        }
    }

    device_type = recognition.classify_device(device_data)
    assert device_type == 'printer'


def test_classify_nas(recognition):
    """Test classifying NAS device"""
    device_data = {
        'hostname': 'synology-nas',
        'vendor': 'Synology',
        'metadata': {
            'ports': [
                {'port': '445', 'state': 'open'},
                {'port': '5000', 'state': 'open'},
            ]
        }
    }

    device_type = recognition.classify_device(device_data)
    assert device_type == 'nas'


def test_classify_workstation_windows(recognition):
    """Test classifying Windows workstation"""
    device_data = {
        'hostname': 'desktop-pc',
        'os_name': 'Windows 10',
        'metadata': {
            'ports': []
        }
    }

    device_type = recognition.classify_device(device_data)
    assert device_type == 'workstation'


def test_classify_unknown(recognition):
    """Test classifying unknown device"""
    device_data = {
        'hostname': 'unknown-device',
        'metadata': {
            'ports': []
        }
    }

    device_type = recognition.classify_device(device_data)
    assert device_type == 'unknown'


def test_get_vendor_from_mac(recognition):
    """Test getting vendor from MAC address"""
    # This test would need OUI data in database
    # For now, test that it returns None for unknown OUI
    vendor = recognition.get_vendor_from_mac('FF:FF:FF:FF:FF:FF')
    assert vendor is None


def test_enrich_device_data(recognition):
    """Test enriching device data"""
    device_data = {
        'ip_address': '192.168.1.100',
        'hostname': 'test-server',
        'os_name': 'Linux',
        'metadata': {
            'ports': [
                {'port': '22', 'state': 'open'},
                {'port': '80', 'state': 'open'},
            ]
        }
    }

    enriched = recognition.enrich_device_data(device_data)

    assert 'device_type' in enriched
    assert 'classification_confidence' in enriched
    assert enriched['device_type'] in ['server', 'workstation', 'unknown']


def test_calculate_confidence(recognition):
    """Test confidence calculation"""
    # High confidence device
    device_high = {
        'os_name': 'Linux',
        'vendor': 'Dell',
        'hostname': 'server01',
        'metadata': {
            'open_ports_count': 5,
            'ports': [
                {'service': {'name': 'ssh'}},
                {'service': {'name': 'http'}},
            ]
        }
    }

    confidence_high = recognition._calculate_confidence(device_high)
    assert confidence_high == 'high'

    # Low confidence device
    device_low = {
        'metadata': {}
    }

    confidence_low = recognition._calculate_confidence(device_low)
    assert confidence_low == 'low'
