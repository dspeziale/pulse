"""
Nmap XML output parser
Converts Nmap XML output into Python objects
"""

import xml.etree.ElementTree as ET
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class NmapParser:
    """Parser for Nmap XML output"""

    def __init__(self):
        """Initialize parser"""
        pass

    def parse_xml(self, xml_output: str) -> Dict[str, Any]:
        """
        Parse Nmap XML output

        Args:
            xml_output: XML string from Nmap

        Returns:
            Dictionary with parsed scan results
        """
        if not xml_output:
            return {'error': 'Empty XML output'}

        try:
            root = ET.fromstring(xml_output)

            # Parse scan info
            scan_info = self._parse_scan_info(root)

            # Parse hosts
            hosts = []
            for host_elem in root.findall('host'):
                host_data = self._parse_host(host_elem)
                if host_data:
                    hosts.append(host_data)

            # Parse run stats
            run_stats = self._parse_run_stats(root)

            result = {
                'scan_info': scan_info,
                'hosts': hosts,
                'run_stats': run_stats,
                'hosts_up': run_stats.get('hosts_up', 0),
                'hosts_down': run_stats.get('hosts_down', 0),
                'hosts_total': run_stats.get('hosts_total', 0)
            }

            return result

        except ET.ParseError as e:
            logger.error(f"XML parse error: {e}")
            return {'error': f'XML parse error: {e}'}
        except Exception as e:
            logger.error(f"Error parsing XML: {e}")
            return {'error': f'Error parsing XML: {e}'}

    def _parse_scan_info(self, root: ET.Element) -> Dict[str, Any]:
        """Parse scan information"""
        scan_info = {}

        # Nmap version and command
        scan_info['nmap_version'] = root.get('version', '')
        scan_info['args'] = root.get('args', '')

        # Scan info element
        scaninfo_elem = root.find('scaninfo')
        if scaninfo_elem is not None:
            scan_info['type'] = scaninfo_elem.get('type', '')
            scan_info['protocol'] = scaninfo_elem.get('protocol', '')
            scan_info['services'] = scaninfo_elem.get('services', '')

        # Start time
        scan_info['start_time'] = root.get('start', '')
        if scan_info['start_time']:
            try:
                scan_info['start_time'] = datetime.fromtimestamp(
                    int(scan_info['start_time'])
                ).isoformat()
            except:
                pass

        return scan_info

    def _parse_host(self, host_elem: ET.Element) -> Optional[Dict[str, Any]]:
        """Parse host information"""
        # Check host status
        status_elem = host_elem.find('status')
        if status_elem is None:
            return None

        host_data = {
            'status': status_elem.get('state', 'unknown'),
            'reason': status_elem.get('reason', '')
        }

        # Parse addresses
        addresses = self._parse_addresses(host_elem)
        host_data.update(addresses)

        # Parse hostnames
        hostnames = self._parse_hostnames(host_elem)
        if hostnames:
            host_data['hostnames'] = hostnames
            host_data['hostname'] = hostnames[0] if hostnames else None

        # Parse OS detection
        os_info = self._parse_os(host_elem)
        if os_info:
            host_data['os'] = os_info

        # Parse ports
        ports = self._parse_ports(host_elem)
        if ports:
            host_data['ports'] = ports

        # Parse host scripts
        host_scripts = self._parse_host_scripts(host_elem)
        if host_scripts:
            host_data['host_scripts'] = host_scripts

        # Parse uptime
        uptime_elem = host_elem.find('uptime')
        if uptime_elem is not None:
            host_data['uptime'] = {
                'seconds': uptime_elem.get('seconds', ''),
                'lastboot': uptime_elem.get('lastboot', '')
            }

        # Parse distance
        distance_elem = host_elem.find('distance')
        if distance_elem is not None:
            host_data['distance'] = distance_elem.get('value', '')

        return host_data

    def _parse_addresses(self, host_elem: ET.Element) -> Dict[str, Any]:
        """Parse host addresses"""
        addresses = {}

        for addr_elem in host_elem.findall('address'):
            addr_type = addr_elem.get('addrtype', 'unknown')
            addr = addr_elem.get('addr', '')

            if addr_type == 'ipv4':
                addresses['ip_address'] = addr
            elif addr_type == 'ipv6':
                addresses['ipv6_address'] = addr
            elif addr_type == 'mac':
                addresses['mac_address'] = addr
                vendor = addr_elem.get('vendor', '')
                if vendor:
                    addresses['vendor'] = vendor

        return addresses

    def _parse_hostnames(self, host_elem: ET.Element) -> List[str]:
        """Parse hostnames"""
        hostnames = []
        hostnames_elem = host_elem.find('hostnames')

        if hostnames_elem is not None:
            for hostname_elem in hostnames_elem.findall('hostname'):
                name = hostname_elem.get('name', '')
                if name:
                    hostnames.append(name)

        return hostnames

    def _parse_os(self, host_elem: ET.Element) -> Optional[Dict[str, Any]]:
        """Parse OS detection information"""
        os_elem = host_elem.find('os')
        if os_elem is None:
            return None

        os_info = {
            'matches': [],
            'classes': []
        }

        # Parse OS matches
        for match_elem in os_elem.findall('osmatch'):
            match = {
                'name': match_elem.get('name', ''),
                'accuracy': match_elem.get('accuracy', ''),
                'line': match_elem.get('line', '')
            }

            # Parse OS classes
            classes = []
            for class_elem in match_elem.findall('osclass'):
                os_class = {
                    'type': class_elem.get('type', ''),
                    'vendor': class_elem.get('vendor', ''),
                    'osfamily': class_elem.get('osfamily', ''),
                    'osgen': class_elem.get('osgen', ''),
                    'accuracy': class_elem.get('accuracy', '')
                }

                # Parse CPE
                cpe_elems = class_elem.findall('cpe')
                if cpe_elems:
                    os_class['cpe'] = [elem.text for elem in cpe_elems if elem.text]

                classes.append(os_class)

            match['classes'] = classes
            os_info['matches'].append(match)

        # Get best match (highest accuracy)
        if os_info['matches']:
            best_match = max(os_info['matches'], key=lambda x: int(x.get('accuracy', 0)))
            os_info['best_match'] = best_match

        return os_info if os_info['matches'] else None

    def _parse_ports(self, host_elem: ET.Element) -> List[Dict[str, Any]]:
        """Parse port information"""
        ports = []
        ports_elem = host_elem.find('ports')

        if ports_elem is None:
            return ports

        for port_elem in ports_elem.findall('port'):
            port_data = {
                'port': port_elem.get('portid', ''),
                'protocol': port_elem.get('protocol', 'tcp')
            }

            # State
            state_elem = port_elem.find('state')
            if state_elem is not None:
                port_data['state'] = state_elem.get('state', '')
                port_data['reason'] = state_elem.get('reason', '')

            # Service
            service_elem = port_elem.find('service')
            if service_elem is not None:
                port_data['service'] = {
                    'name': service_elem.get('name', ''),
                    'product': service_elem.get('product', ''),
                    'version': service_elem.get('version', ''),
                    'extrainfo': service_elem.get('extrainfo', ''),
                    'ostype': service_elem.get('ostype', ''),
                    'method': service_elem.get('method', ''),
                    'conf': service_elem.get('conf', '')
                }

                # CPE
                cpe_elems = service_elem.findall('cpe')
                if cpe_elems:
                    port_data['service']['cpe'] = [elem.text for elem in cpe_elems if elem.text]

            # Scripts
            scripts = []
            for script_elem in port_elem.findall('script'):
                script = {
                    'id': script_elem.get('id', ''),
                    'output': script_elem.get('output', '')
                }

                # Parse script elements
                elem_data = {}
                for elem in script_elem.findall('elem'):
                    key = elem.get('key', '')
                    value = elem.text or ''
                    if key:
                        elem_data[key] = value

                if elem_data:
                    script['data'] = elem_data

                scripts.append(script)

            if scripts:
                port_data['scripts'] = scripts

            ports.append(port_data)

        return ports

    def _parse_host_scripts(self, host_elem: ET.Element) -> List[Dict[str, Any]]:
        """Parse host-level scripts"""
        scripts = []
        hostscript_elem = host_elem.find('hostscript')

        if hostscript_elem is None:
            return scripts

        for script_elem in hostscript_elem.findall('script'):
            script = {
                'id': script_elem.get('id', ''),
                'output': script_elem.get('output', '')
            }

            # Parse script elements
            elem_data = {}
            for elem in script_elem.findall('elem'):
                key = elem.get('key', '')
                value = elem.text or ''
                if key:
                    elem_data[key] = value

            if elem_data:
                script['data'] = elem_data

            scripts.append(script)

        return scripts

    def _parse_run_stats(self, root: ET.Element) -> Dict[str, Any]:
        """Parse run statistics"""
        stats = {}

        runstats_elem = root.find('runstats')
        if runstats_elem is None:
            return stats

        # Finished time
        finished_elem = runstats_elem.find('finished')
        if finished_elem is not None:
            stats['end_time'] = finished_elem.get('timestr', '')
            stats['elapsed'] = finished_elem.get('elapsed', '')

        # Hosts stats
        hosts_elem = runstats_elem.find('hosts')
        if hosts_elem is not None:
            stats['hosts_up'] = int(hosts_elem.get('up', 0))
            stats['hosts_down'] = int(hosts_elem.get('down', 0))
            stats['hosts_total'] = int(hosts_elem.get('total', 0))

        return stats

    def extract_devices(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract device information from parsed data

        Args:
            parsed_data: Parsed Nmap XML data

        Returns:
            List of device dictionaries suitable for database storage
        """
        devices = []

        for host in parsed_data.get('hosts', []):
            if host.get('status') != 'up':
                continue

            device = {
                'ip_address': host.get('ip_address'),
                'mac_address': host.get('mac_address'),
                'hostname': host.get('hostname'),
                'vendor': host.get('vendor'),
                'status': host.get('status'),
                'metadata': {}
            }

            # Extract OUI from MAC
            if device['mac_address']:
                oui = device['mac_address'][:8].replace(':', '').upper()
                device['oui'] = oui

            # Extract OS information
            os_info = host.get('os')
            if os_info and os_info.get('best_match'):
                best_match = os_info['best_match']
                device['os_name'] = best_match.get('name')
                device['os_accuracy'] = int(best_match.get('accuracy', 0))

                # Get OS family from first class
                classes = best_match.get('classes', [])
                if classes:
                    device['os_family'] = classes[0].get('osfamily')
                    device['os_version'] = classes[0].get('osgen')

            # Extract ports
            ports = host.get('ports', [])
            if ports:
                device['metadata']['ports'] = ports
                device['metadata']['open_ports_count'] = len(
                    [p for p in ports if p.get('state') == 'open']
                )

            # Extract additional metadata
            if host.get('hostnames'):
                device['metadata']['all_hostnames'] = host['hostnames']

            if host.get('uptime'):
                device['metadata']['uptime'] = host['uptime']

            if host.get('distance'):
                device['metadata']['distance'] = host['distance']

            devices.append(device)

        return devices


def create_parser() -> NmapParser:
    """Factory function to create parser instance"""
    return NmapParser()
