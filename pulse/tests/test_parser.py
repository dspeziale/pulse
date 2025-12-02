"""Tests for Nmap parser module"""

import pytest
from pulse.parser.nmap_parser import NmapParser


SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sn 192.168.1.0/24" start="1234567890" version="7.80">
    <scaninfo type="ping" protocol="ip" numservices="0"/>
    <host starttime="1234567890" endtime="1234567891">
        <status state="up" reason="arp-response"/>
        <address addr="192.168.1.100" addrtype="ipv4"/>
        <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Test Vendor"/>
        <hostnames>
            <hostname name="test-host.local" type="PTR"/>
        </hostnames>
    </host>
    <host starttime="1234567892" endtime="1234567893">
        <status state="up" reason="arp-response"/>
        <address addr="192.168.1.101" addrtype="ipv4"/>
        <address addr="11:22:33:44:55:66" addrtype="mac"/>
        <ports>
            <port protocol="tcp" portid="80">
                <state state="open" reason="syn-ack"/>
                <service name="http" product="Apache" version="2.4.41" method="probed" conf="10"/>
            </port>
            <port protocol="tcp" portid="443">
                <state state="open" reason="syn-ack"/>
                <service name="https" product="Apache" version="2.4.41" method="probed" conf="10"/>
            </port>
        </ports>
    </host>
    <runstats>
        <finished time="1234567900" timestr="Test Time" elapsed="10"/>
        <hosts up="2" down="0" total="2"/>
    </runstats>
</nmaprun>
"""


@pytest.fixture
def parser():
    """Create parser instance"""
    return NmapParser()


def test_parser_initialization(parser):
    """Test parser initialization"""
    assert parser is not None


def test_parse_empty_xml(parser):
    """Test parsing empty XML"""
    result = parser.parse_xml("")
    assert 'error' in result


def test_parse_valid_xml(parser):
    """Test parsing valid Nmap XML"""
    result = parser.parse_xml(SAMPLE_XML)

    assert 'error' not in result
    assert 'scan_info' in result
    assert 'hosts' in result
    assert 'run_stats' in result


def test_parse_hosts(parser):
    """Test parsing host information"""
    result = parser.parse_xml(SAMPLE_XML)

    assert len(result['hosts']) == 2

    # First host
    host1 = result['hosts'][0]
    assert host1['status'] == 'up'
    assert host1['ip_address'] == '192.168.1.100'
    assert host1['mac_address'] == 'AA:BB:CC:DD:EE:FF'
    assert host1['vendor'] == 'Test Vendor'
    assert host1['hostname'] == 'test-host.local'


def test_parse_ports(parser):
    """Test parsing port information"""
    result = parser.parse_xml(SAMPLE_XML)

    # Second host has ports
    host2 = result['hosts'][1]
    assert 'ports' in host2
    assert len(host2['ports']) == 2

    # Check first port
    port1 = host2['ports'][0]
    assert port1['port'] == '80'
    assert port1['protocol'] == 'tcp'
    assert port1['state'] == 'open'
    assert port1['service']['name'] == 'http'
    assert port1['service']['product'] == 'Apache'


def test_parse_run_stats(parser):
    """Test parsing run statistics"""
    result = parser.parse_xml(SAMPLE_XML)

    stats = result['run_stats']
    assert stats['hosts_up'] == 2
    assert stats['hosts_down'] == 0
    assert stats['hosts_total'] == 2
    assert stats['elapsed'] == '10'


def test_extract_devices(parser):
    """Test extracting device information"""
    result = parser.parse_xml(SAMPLE_XML)
    devices = parser.extract_devices(result)

    assert len(devices) == 2

    # Check first device
    device1 = devices[0]
    assert device1['ip_address'] == '192.168.1.100'
    assert device1['mac_address'] == 'AA:BB:CC:DD:EE:FF'
    assert device1['hostname'] == 'test-host.local'
    assert device1['vendor'] == 'Test Vendor'
    assert device1['status'] == 'up'

    # Check OUI extraction
    assert 'oui' in device1


def test_extract_devices_with_ports(parser):
    """Test extracting devices with port information"""
    result = parser.parse_xml(SAMPLE_XML)
    devices = parser.extract_devices(result)

    # Second device has ports
    device2 = devices[1]
    assert 'ports' in device2['metadata']
    assert device2['metadata']['open_ports_count'] == 2
