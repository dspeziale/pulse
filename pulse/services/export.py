"""
Data export service for various formats (JSON, CSV, HTML, XML)
"""

import json
import csv
import logging
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from io import StringIO

from pulse.storage.db import get_db
from pulse.utils.config import get_config

logger = logging.getLogger(__name__)


class ExportService:
    """Data export service"""

    def __init__(self, config=None, db=None):
        """Initialize export service"""
        self.config = config or get_config()
        self.db = db or get_db()

        self.output_dir = self.config.get('export.output_dir', 'exports')
        os.makedirs(self.output_dir, exist_ok=True)

    def export_devices(self, format: str = 'json', filename: str = None) -> str:
        """
        Export devices to file

        Args:
            format: Export format (json, csv, html, xml)
            filename: Output filename (auto-generated if None)

        Returns:
            Path to exported file
        """
        devices = self.db.get_all_devices(active_only=False)

        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"devices_{timestamp}.{format}"

        filepath = os.path.join(self.output_dir, filename)

        if format == 'json':
            self._export_json(devices, filepath)
        elif format == 'csv':
            self._export_csv(devices, filepath)
        elif format == 'html':
            self._export_html(devices, filepath)
        elif format == 'xml':
            self._export_xml(devices, filepath)
        else:
            raise ValueError(f"Unsupported format: {format}")

        logger.info(f"Exported {len(devices)} devices to {filepath}")
        return filepath

    def export_scan_results(self, format: str = 'json', filename: str = None, limit: int = 50) -> str:
        """
        Export scan results to file

        Args:
            format: Export format
            filename: Output filename
            limit: Number of results to export

        Returns:
            Path to exported file
        """
        results = self.db.get_scan_results(limit=limit)

        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"scan_results_{timestamp}.{format}"

        filepath = os.path.join(self.output_dir, filename)

        if format == 'json':
            self._export_json(results, filepath)
        elif format == 'csv':
            self._export_csv(results, filepath)
        elif format == 'html':
            self._export_html(results, filepath, 'Scan Results')
        elif format == 'xml':
            self._export_xml(results, filepath, 'scan_results')
        else:
            raise ValueError(f"Unsupported format: {format}")

        logger.info(f"Exported {len(results)} scan results to {filepath}")
        return filepath

    def export_events(self, format: str = 'json', filename: str = None, limit: int = 100) -> str:
        """
        Export events to file

        Args:
            format: Export format
            filename: Output filename
            limit: Number of events to export

        Returns:
            Path to exported file
        """
        events = self.db.get_events(limit=limit)

        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"events_{timestamp}.{format}"

        filepath = os.path.join(self.output_dir, filename)

        if format == 'json':
            self._export_json(events, filepath)
        elif format == 'csv':
            self._export_csv(events, filepath)
        elif format == 'html':
            self._export_html(events, filepath, 'Events')
        elif format == 'xml':
            self._export_xml(events, filepath, 'events')
        else:
            raise ValueError(f"Unsupported format: {format}")

        logger.info(f"Exported {len(events)} events to {filepath}")
        return filepath

    def _export_json(self, data: List[Dict], filepath: str):
        """Export data as JSON"""
        with open(filepath, 'w') as f:
            json.dump({
                'exported_at': datetime.now().isoformat(),
                'count': len(data),
                'data': data
            }, f, indent=2, default=str)

    def _export_csv(self, data: List[Dict], filepath: str):
        """Export data as CSV"""
        if not data:
            with open(filepath, 'w') as f:
                f.write('')
            return

        # Get all keys from all records
        keys = set()
        for record in data:
            keys.update(record.keys())

        keys = sorted(keys)

        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()

            for record in data:
                # Convert complex types to strings
                row = {}
                for key in keys:
                    value = record.get(key)
                    if isinstance(value, (dict, list)):
                        row[key] = json.dumps(value)
                    else:
                        row[key] = value
                writer.writerow(row)

    def _export_html(self, data: List[Dict], filepath: str, title: str = 'Pulse Export'):
        """Export data as HTML table"""
        if not data:
            keys = []
        else:
            keys = set()
            for record in data:
                keys.update(record.keys())
            keys = sorted(keys)

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .meta {{ color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    <p class="meta">Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Records: {len(data)}</p>
    <table>
        <thead>
            <tr>
"""

        for key in keys:
            html += f"                <th>{key}</th>\n"

        html += """            </tr>
        </thead>
        <tbody>
"""

        for record in data:
            html += "            <tr>\n"
            for key in keys:
                value = record.get(key, '')
                if isinstance(value, (dict, list)):
                    value = json.dumps(value)
                html += f"                <td>{value}</td>\n"
            html += "            </tr>\n"

        html += """        </tbody>
    </table>
</body>
</html>
"""

        with open(filepath, 'w') as f:
            f.write(html)

    def _export_xml(self, data: List[Dict], filepath: str, root_tag: str = 'data'):
        """Export data as XML"""
        xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
        xml += f'<{root_tag}>\n'
        xml += f'  <exported_at>{datetime.now().isoformat()}</exported_at>\n'
        xml += f'  <count>{len(data)}</count>\n'
        xml += '  <records>\n'

        for record in data:
            xml += '    <record>\n'
            for key, value in record.items():
                # Sanitize tag name
                tag = key.replace(' ', '_').replace('-', '_')

                if isinstance(value, (dict, list)):
                    value = json.dumps(value)
                elif value is None:
                    value = ''

                # Escape XML special characters
                value = str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

                xml += f'      <{tag}>{value}</{tag}>\n'
            xml += '    </record>\n'

        xml += '  </records>\n'
        xml += f'</{root_tag}>\n'

        with open(filepath, 'w') as f:
            f.write(xml)


# Global instance
_export_service = None


def get_export_service(config=None, db=None) -> ExportService:
    """Get export service singleton instance"""
    global _export_service
    if _export_service is None:
        _export_service = ExportService(config, db)
    return _export_service
