"""Tests for database module"""

import pytest
import tempfile
import os

from pulse.storage.db import Database


@pytest.fixture
def temp_db():
    """Create temporary database for testing"""
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)

    db = Database(path)
    yield db

    db.close()
    if os.path.exists(path):
        os.unlink(path)


def test_database_initialization(temp_db):
    """Test database initialization"""
    assert temp_db is not None
    assert os.path.exists(temp_db.db_path)


def test_add_device(temp_db):
    """Test adding a device"""
    device_data = {
        'ip_address': '192.168.1.100',
        'mac_address': 'AA:BB:CC:DD:EE:FF',
        'hostname': 'test-device',
        'vendor': 'Test Vendor',
        'device_type': 'server',
        'status': 'up'
    }

    device_id = temp_db.add_device(device_data)
    assert device_id > 0

    # Retrieve device
    device = temp_db.get_device(device_id=device_id)
    assert device is not None
    assert device['ip_address'] == '192.168.1.100'
    assert device['hostname'] == 'test-device'


def test_get_device_by_ip(temp_db):
    """Test getting device by IP address"""
    device_data = {
        'ip_address': '192.168.1.101',
        'mac_address': '11:22:33:44:55:66',
        'hostname': 'test-host',
        'status': 'up'
    }

    temp_db.add_device(device_data)

    device = temp_db.get_device(ip_address='192.168.1.101')
    assert device is not None
    assert device['ip_address'] == '192.168.1.101'


def test_update_device(temp_db):
    """Test updating device (via upsert)"""
    device_data = {
        'ip_address': '192.168.1.102',
        'hostname': 'old-hostname',
        'status': 'up'
    }

    # First insert
    temp_db.add_device(device_data)

    # Update via upsert
    device_data['hostname'] = 'new-hostname'
    temp_db.add_device(device_data)

    # Verify update
    device = temp_db.get_device(ip_address='192.168.1.102')
    assert device['hostname'] == 'new-hostname'


def test_create_scan_task(temp_db):
    """Test creating scan task"""
    task_data = {
        'task_type': 'discovery',
        'target': '192.168.1.0/24',
        'status': 'pending',
        'priority': 5
    }

    task_id = temp_db.create_scan_task(task_data)
    assert task_id > 0

    # Retrieve task
    task = temp_db.get_task(task_id)
    assert task is not None
    assert task['task_type'] == 'discovery'
    assert task['target'] == '192.168.1.0/24'


def test_get_pending_tasks(temp_db):
    """Test getting pending tasks"""
    # Create multiple tasks
    for i in range(5):
        temp_db.create_scan_task({
            'task_type': 'quick',
            'target': f'192.168.1.{i}',
            'status': 'pending'
        })

    pending = temp_db.get_pending_tasks(limit=10)
    assert len(pending) == 5


def test_add_port(temp_db):
    """Test adding port to device"""
    # First add device
    device_id = temp_db.add_device({
        'ip_address': '192.168.1.103',
        'status': 'up'
    })

    # Add port
    port_data = {
        'device_id': device_id,
        'port_number': 80,
        'protocol': 'tcp',
        'state': 'open',
        'service_name': 'http'
    }

    port_id = temp_db.add_port(port_data)
    assert port_id > 0

    # Retrieve ports
    ports = temp_db.get_device_ports(device_id)
    assert len(ports) == 1
    assert ports[0]['port_number'] == 80


def test_create_event(temp_db):
    """Test creating event"""
    event_data = {
        'event_type': 'device_discovered',
        'severity': 'info',
        'title': 'New device found',
        'description': 'A new device has been discovered'
    }

    event_id = temp_db.create_event(event_data)
    assert event_id > 0

    # Retrieve events
    events = temp_db.get_events(limit=10)
    assert len(events) == 1
    assert events[0]['title'] == 'New device found'


def test_config_operations(temp_db):
    """Test configuration operations"""
    # Set config
    temp_db.set_config('test.key', 'test_value', 'Test configuration')

    # Get config
    value = temp_db.get_config('test.key')
    assert value == 'test_value'

    # Get all config
    all_config = temp_db.get_all_config()
    assert 'test.key' in all_config


def test_oui_operations(temp_db):
    """Test OUI cache operations"""
    # Add OUI
    temp_db.add_oui('AABBCC', 'Test Vendor Inc.')

    # Get vendor
    vendor = temp_db.get_oui_vendor('AABBCC')
    assert vendor == 'Test Vendor Inc.'

    # Test bulk insert
    oui_data = [
        ('112233', 'Vendor 1'),
        ('445566', 'Vendor 2'),
        ('778899', 'Vendor 3')
    ]

    temp_db.bulk_insert_oui(oui_data)

    assert temp_db.get_oui_vendor('112233') == 'Vendor 1'
    assert temp_db.get_oui_vendor('445566') == 'Vendor 2'
