"""
Device recognition and classification service
Uses OUI, ports, services, and OS fingerprinting to identify device types
"""

import logging
import re
from typing import Dict, List, Any, Optional, Set

from pulse.storage.db import get_db
from pulse.utils.config import get_config

logger = logging.getLogger(__name__)


class DeviceRecognition:
    """Device type recognition and classification"""

    def __init__(self, config=None, db=None):
        """Initialize device recognition"""
        self.config = config or get_config()
        self.db = db or get_db()

        # Load classification rules from config
        self.classification_rules = self.config.get('recognition.classification', {})

    def classify_device(self, device_data: Dict[str, Any]) -> str:
        """
        Classify device type based on available information

        Args:
            device_data: Device data dictionary

        Returns:
            Device type string
        """
        # Extract relevant information
        hostname = (device_data.get('hostname') or '').lower()
        vendor = (device_data.get('vendor') or '').lower()
        os_name = (device_data.get('os_name') or '').lower()
        os_family = (device_data.get('os_family') or '').lower()

        # Get open ports
        open_ports = set()
        if device_data.get('metadata', {}).get('ports'):
            for port in device_data['metadata']['ports']:
                if port.get('state') == 'open':
                    port_num = port.get('port')
                    if port_num:
                        open_ports.add(int(port_num))

        # Get service names
        services = set()
        if device_data.get('metadata', {}).get('ports'):
            for port in device_data['metadata']['ports']:
                if port.get('state') == 'open':
                    service = port.get('service', {})
                    service_name = service.get('name')
                    if service_name:
                        services.add(service_name.lower())

        # Combine text for keyword matching
        text = f"{hostname} {vendor} {os_name} {os_family}".lower()

        # Score each device type
        scores = {}

        for device_type, rules in self.classification_rules.items():
            score = 0

            # Check ports
            if 'ports' in rules:
                rule_ports = set(rules['ports'])
                matching_ports = open_ports.intersection(rule_ports)
                if matching_ports:
                    score += len(matching_ports) * 10

            # Check keywords
            if 'keywords' in rules:
                for keyword in rules['keywords']:
                    if keyword.lower() in text:
                        score += 20

            # Check services
            if 'services' in rules:
                rule_services = set(s.lower() for s in rules['services'])
                matching_services = services.intersection(rule_services)
                if matching_services:
                    score += len(matching_services) * 15

            if score > 0:
                scores[device_type] = score

        # Return device type with highest score
        if scores:
            best_type = max(scores, key=scores.get)
            logger.debug(f"Classified device as {best_type} (score: {scores[best_type]})")
            return best_type

        # Default classifications based on OS
        if 'windows' in os_name or 'windows' in os_family:
            return 'workstation'
        elif any(x in os_name or x in os_family for x in ['linux', 'unix', 'bsd']):
            # Check if it's a server (has server ports)
            server_ports = {22, 80, 443, 3306, 5432, 6379, 8080}
            if open_ports.intersection(server_ports):
                return 'server'
            return 'workstation'
        elif 'android' in os_name or 'ios' in os_name:
            return 'mobile'

        # Default to unknown
        return 'unknown'

    def get_vendor_from_mac(self, mac_address: str) -> Optional[str]:
        """
        Get vendor from MAC address using OUI lookup

        Args:
            mac_address: MAC address (XX:XX:XX:XX:XX:XX)

        Returns:
            Vendor name or None
        """
        if not mac_address:
            return None

        # Extract OUI (first 3 bytes)
        oui = mac_address[:8].replace(':', '').upper()

        # Check database cache
        vendor = self.db.get_oui_vendor(oui)

        if vendor:
            logger.debug(f"Found vendor for MAC {mac_address}: {vendor}")
            return vendor

        logger.debug(f"No vendor found for MAC {mac_address} (OUI: {oui})")
        return None

    def enrich_device_data(self, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich device data with classification and vendor information

        Args:
            device_data: Device data dictionary

        Returns:
            Enriched device data
        """
        enriched = device_data.copy()

        # Get vendor from MAC if not already set
        if not enriched.get('vendor') and enriched.get('mac_address'):
            vendor = self.get_vendor_from_mac(enriched['mac_address'])
            if vendor:
                enriched['vendor'] = vendor

        # Classify device type
        device_type = self.classify_device(enriched)
        enriched['device_type'] = device_type

        # Add confidence score
        enriched['classification_confidence'] = self._calculate_confidence(enriched)

        return enriched

    def _calculate_confidence(self, device_data: Dict[str, Any]) -> str:
        """Calculate classification confidence level"""
        score = 0

        # Has OS information
        if device_data.get('os_name'):
            score += 30

        # Has vendor information
        if device_data.get('vendor'):
            score += 20

        # Has hostname
        if device_data.get('hostname'):
            score += 20

        # Has open ports
        if device_data.get('metadata', {}).get('open_ports_count', 0) > 0:
            score += 20

        # Has service information
        ports = device_data.get('metadata', {}).get('ports', [])
        if any(p.get('service', {}).get('name') for p in ports):
            score += 10

        if score >= 70:
            return 'high'
        elif score >= 40:
            return 'medium'
        else:
            return 'low'

    def identify_suspicious_devices(self) -> List[Dict[str, Any]]:
        """
        Identify potentially suspicious devices based on patterns

        Returns:
            List of suspicious device information
        """
        suspicious = []

        # Get all active devices
        devices = self.db.get_all_devices(active_only=True)

        for device in devices:
            device_id = device['id']
            ip_address = device['ip_address']
            suspicion_reasons = []

            # Get device ports
            ports = self.db.get_device_ports(device_id)
            open_ports = [p for p in ports if p['state'] == 'open']

            # Check for suspicious ports
            suspicious_ports = self.config.get('alerts.rules.suspicious_port.ports', [23, 445, 3389])

            for port in open_ports:
                if port['port_number'] in suspicious_ports:
                    suspicion_reasons.append(
                        f"Suspicious port {port['port_number']} ({port.get('service_name', 'unknown')})"
                    )

            # Check for devices without proper identification
            if not device.get('hostname') and not device.get('vendor'):
                suspicion_reasons.append("No hostname or vendor information")

            # Check for unusual number of open ports
            if len(open_ports) > 50:
                suspicion_reasons.append(f"Unusual number of open ports ({len(open_ports)})")

            # Check for unknown device type
            if device.get('device_type') == 'unknown' and len(open_ports) > 5:
                suspicion_reasons.append("Unknown device type with multiple open ports")

            if suspicion_reasons:
                suspicious.append({
                    'device_id': device_id,
                    'ip_address': ip_address,
                    'hostname': device.get('hostname'),
                    'mac_address': device.get('mac_address'),
                    'vendor': device.get('vendor'),
                    'device_type': device.get('device_type'),
                    'reasons': suspicion_reasons,
                    'severity': self._calculate_suspicion_severity(suspicion_reasons)
                })

        return suspicious

    def _calculate_suspicion_severity(self, reasons: List[str]) -> str:
        """Calculate severity level based on suspicion reasons"""
        if len(reasons) >= 3:
            return 'critical'
        elif len(reasons) == 2:
            return 'high'
        elif any('suspicious port' in r.lower() for r in reasons):
            return 'high'
        else:
            return 'medium'

    def get_device_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about devices on the network

        Returns:
            Statistics dictionary
        """
        devices = self.db.get_all_devices(active_only=True)

        stats = {
            'total_devices': len(devices),
            'by_type': {},
            'by_vendor': {},
            'by_os': {},
            'with_hostname': 0,
            'without_hostname': 0,
            'with_mac': 0,
            'without_mac': 0
        }

        for device in devices:
            # Count by type (handle None values)
            device_type = device.get('device_type') or 'unknown'
            stats['by_type'][device_type] = stats['by_type'].get(device_type, 0) + 1

            # Count by vendor (handle None values)
            vendor = device.get('vendor') or 'Unknown'
            stats['by_vendor'][vendor] = stats['by_vendor'].get(vendor, 0) + 1

            # Count by OS (handle None values)
            os_family = device.get('os_family') or 'Unknown'
            stats['by_os'][os_family] = stats['by_os'].get(os_family, 0) + 1

            # Count hostnames
            if device.get('hostname'):
                stats['with_hostname'] += 1
            else:
                stats['without_hostname'] += 1

            # Count MACs
            if device.get('mac_address'):
                stats['with_mac'] += 1
            else:
                stats['without_mac'] += 1

        return stats


# Global instance
_recognition_service = None


def get_recognition_service(config=None, db=None) -> DeviceRecognition:
    """Get device recognition service singleton instance"""
    global _recognition_service
    if _recognition_service is None:
        _recognition_service = DeviceRecognition(config, db)
    return _recognition_service
