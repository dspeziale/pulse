"""
Scanner engine for network discovery and scanning using Nmap
"""

import subprocess
import tempfile
import os
import logging
from typing import Optional, Dict, List, Any, Tuple
from datetime import datetime
import shlex

logger = logging.getLogger(__name__)


class ScanType:
    """Scan type constants"""
    DISCOVERY = "discovery"
    QUICK = "quick"
    DEEP = "deep"
    FULL = "full"
    CUSTOM = "custom"


class NmapScanner:
    """Nmap scanner wrapper"""

    def __init__(self, config=None):
        """Initialize scanner"""
        self.config = config
        self.nmap_path = self._find_nmap()

        if not self.nmap_path:
            raise RuntimeError("Nmap not found in system PATH")

        logger.info(f"Nmap found at: {self.nmap_path}")

    def _find_nmap(self) -> Optional[str]:
        """Find nmap executable in system"""
        try:
            result = subprocess.run(
                ['which', 'nmap'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception as e:
            logger.error(f"Error finding nmap: {e}")

        return None

    def get_nmap_version(self) -> str:
        """Get Nmap version"""
        try:
            result = subprocess.run(
                [self.nmap_path, '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                if lines:
                    return lines[0].strip()
        except Exception as e:
            logger.error(f"Error getting nmap version: {e}")

        return "Unknown"

    def _build_command(
        self,
        target: str,
        scan_type: str,
        options: str = None,
        xml_output: str = None
    ) -> List[str]:
        """Build nmap command"""
        cmd = [self.nmap_path]

        # Add scan type options
        if options:
            # Custom options provided
            cmd.extend(shlex.split(options))
        elif scan_type == ScanType.DISCOVERY:
            # Discovery scan (ping scan, no port scan)
            if self.config:
                opts = self.config.get('scanner.nmap.discovery_options', '-sn -T4')
            else:
                opts = '-sn -T4'
            cmd.extend(shlex.split(opts))
        elif scan_type == ScanType.QUICK:
            # Quick port scan (top 100 ports)
            if self.config:
                opts = self.config.get('scanner.nmap.quick_scan_options', '-F -sV -T4')
            else:
                opts = '-F -sV -T4'
            cmd.extend(shlex.split(opts))
        elif scan_type == ScanType.DEEP:
            # Deep scan with OS detection and scripts
            if self.config:
                opts = self.config.get('scanner.nmap.deep_scan_options', '-sV -O -A --script=default,discovery -T4')
            else:
                opts = '-sV -O -A --script=default,discovery -T4'
            cmd.extend(shlex.split(opts))
        elif scan_type == ScanType.FULL:
            # Full port scan (all 65535 ports)
            if self.config:
                opts = self.config.get('scanner.nmap.full_scan_options', '-p- -sV -T4')
            else:
                opts = '-p- -sV -T4'
            cmd.extend(shlex.split(opts))

        # Add XML output
        if xml_output:
            cmd.extend(['-oX', xml_output])

        # Add target
        cmd.append(target)

        return cmd

    def scan(
        self,
        target: str,
        scan_type: str = ScanType.DISCOVERY,
        options: str = None,
        timeout: int = 600
    ) -> Dict[str, Any]:
        """
        Execute nmap scan

        Args:
            target: Target IP, network range, or hostname
            scan_type: Type of scan (discovery, quick, deep, full)
            options: Custom nmap options (overrides scan_type)
            timeout: Scan timeout in seconds

        Returns:
            Dictionary with scan results
        """
        start_time = datetime.now()

        # Create temporary file for XML output
        xml_fd, xml_path = tempfile.mkstemp(suffix='.xml', prefix='nmap_')
        os.close(xml_fd)

        try:
            # Build command
            cmd = self._build_command(target, scan_type, options, xml_path)
            cmd_str = ' '.join(cmd)

            logger.info(f"Running scan: {cmd_str}")

            # Execute nmap
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            # Read XML output
            xml_output = None
            if os.path.exists(xml_path) and os.path.getsize(xml_path) > 0:
                with open(xml_path, 'r') as f:
                    xml_output = f.read()

            # Prepare result
            scan_result = {
                'success': result.returncode == 0,
                'return_code': result.returncode,
                'command': cmd_str,
                'target': target,
                'scan_type': scan_type,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration': duration,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'xml_output': xml_output,
                'nmap_version': self.get_nmap_version()
            }

            if result.returncode == 0:
                logger.info(f"Scan completed successfully in {duration:.2f}s")
            else:
                logger.error(f"Scan failed with return code {result.returncode}")
                logger.error(f"Error output: {result.stderr}")

            return scan_result

        except subprocess.TimeoutExpired:
            logger.error(f"Scan timeout after {timeout}s")
            return {
                'success': False,
                'error': f'Scan timeout after {timeout}s',
                'command': ' '.join(cmd),
                'target': target,
                'scan_type': scan_type,
                'start_time': start_time.isoformat(),
                'duration': timeout
            }

        except Exception as e:
            logger.error(f"Scan error: {e}")
            return {
                'success': False,
                'error': str(e),
                'target': target,
                'scan_type': scan_type,
                'start_time': start_time.isoformat()
            }

        finally:
            # Cleanup temporary file
            try:
                if os.path.exists(xml_path):
                    os.unlink(xml_path)
            except Exception as e:
                logger.warning(f"Failed to remove temporary file {xml_path}: {e}")

    def discovery_scan(self, network: str, timeout: int = 300) -> Dict[str, Any]:
        """
        Perform network discovery scan (ping scan)

        Args:
            network: Network range (e.g., 192.168.1.0/24)
            timeout: Scan timeout in seconds

        Returns:
            Scan results dictionary
        """
        return self.scan(network, ScanType.DISCOVERY, timeout=timeout)

    def quick_scan(self, target: str, timeout: int = 300) -> Dict[str, Any]:
        """
        Perform quick port scan (top 100 ports)

        Args:
            target: Target IP or hostname
            timeout: Scan timeout in seconds

        Returns:
            Scan results dictionary
        """
        return self.scan(target, ScanType.QUICK, timeout=timeout)

    def deep_scan(self, target: str, timeout: int = 600) -> Dict[str, Any]:
        """
        Perform deep scan with OS detection and service version detection

        Args:
            target: Target IP or hostname
            timeout: Scan timeout in seconds

        Returns:
            Scan results dictionary
        """
        return self.scan(target, ScanType.DEEP, timeout=timeout)

    def full_scan(self, target: str, timeout: int = 3600) -> Dict[str, Any]:
        """
        Perform full port scan (all 65535 ports)

        Args:
            target: Target IP or hostname
            timeout: Scan timeout in seconds

        Returns:
            Scan results dictionary
        """
        return self.scan(target, ScanType.FULL, timeout=timeout)

    def port_scan(
        self,
        target: str,
        ports: str,
        service_detection: bool = True,
        timeout: int = 300
    ) -> Dict[str, Any]:
        """
        Scan specific ports

        Args:
            target: Target IP or hostname
            ports: Port specification (e.g., "22,80,443" or "1-1000")
            service_detection: Enable service version detection
            timeout: Scan timeout in seconds

        Returns:
            Scan results dictionary
        """
        options = f"-p {ports}"
        if service_detection:
            options += " -sV"
        options += " -T4"

        return self.scan(target, ScanType.CUSTOM, options=options, timeout=timeout)

    def is_nmap_available(self) -> bool:
        """Check if Nmap is available"""
        return self.nmap_path is not None

    def check_requirements(self) -> Tuple[bool, str]:
        """
        Check if all requirements are met

        Returns:
            Tuple of (success, message)
        """
        if not self.is_nmap_available():
            return False, "Nmap is not installed or not found in PATH"

        try:
            version = self.get_nmap_version()
            return True, f"Nmap is available: {version}"
        except Exception as e:
            return False, f"Error checking Nmap: {e}"


def create_scanner(config=None) -> NmapScanner:
    """Factory function to create scanner instance"""
    return NmapScanner(config=config)
