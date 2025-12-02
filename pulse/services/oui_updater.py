"""
OUI (Organizationally Unique Identifier) database updater
Downloads and parses IEEE OUI database for MAC address vendor lookup
"""

import logging
import re
import requests
from datetime import datetime
from typing import List, Tuple, Optional

from pulse.storage.db import get_db
from pulse.utils.config import get_config

logger = logging.getLogger(__name__)


class OUIUpdater:
    """OUI database updater"""

    def __init__(self, config=None, db=None):
        """Initialize OUI updater"""
        self.config = config or get_config()
        self.db = db or get_db()

        self.oui_url = self.config.get('oui.update_url', 'https://standards-oui.ieee.org/oui/oui.txt')

    def update(self) -> Tuple[bool, str]:
        """
        Update OUI database from IEEE

        Returns:
            Tuple of (success, message)
        """
        try:
            logger.info(f"Downloading OUI database from {self.oui_url}")

            # Download OUI file
            response = requests.get(self.oui_url, timeout=60)
            response.raise_for_status()

            content = response.text
            logger.info(f"Downloaded {len(content)} bytes")

            # Parse OUI data
            oui_data = self._parse_oui_file(content)

            if not oui_data:
                return False, "No OUI data parsed"

            logger.info(f"Parsed {len(oui_data)} OUI entries")

            # Update database
            self.db.bulk_insert_oui(oui_data)

            # Update last update timestamp in config
            self.db.set_config('oui.last_update', datetime.now().isoformat())

            logger.info("OUI database updated successfully")
            return True, f"Updated {len(oui_data)} OUI entries"

        except requests.RequestException as e:
            logger.error(f"Error downloading OUI database: {e}")
            return False, f"Download error: {e}"
        except Exception as e:
            logger.error(f"Error updating OUI database: {e}", exc_info=True)
            return False, f"Update error: {e}"

    def _parse_oui_file(self, content: str) -> List[Tuple[str, str]]:
        """
        Parse IEEE OUI text file

        Args:
            content: OUI file content

        Returns:
            List of (oui, vendor) tuples
        """
        oui_data = []

        # Pattern to match OUI entries
        # Format: XX-XX-XX   (hex)		Vendor Name
        pattern = r'([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)'

        for line in content.split('\n'):
            match = re.match(pattern, line)
            if match:
                oui_hex = match.group(1).replace('-', '')
                vendor = match.group(2).strip()

                oui_data.append((oui_hex, vendor))

        return oui_data

    def get_last_update(self) -> Optional[str]:
        """Get last OUI database update timestamp"""
        return self.db.get_config('oui.last_update')

    def should_update(self) -> bool:
        """Check if OUI database should be updated"""
        last_update_str = self.get_last_update()

        if not last_update_str:
            return True

        try:
            last_update = datetime.fromisoformat(last_update_str)
            update_interval = self.config.get('oui.update_interval', 604800)  # 7 days

            elapsed = (datetime.now() - last_update).total_seconds()

            return elapsed >= update_interval

        except Exception as e:
            logger.error(f"Error checking update status: {e}")
            return True


# Global instance
_oui_updater = None


def get_oui_updater(config=None, db=None) -> OUIUpdater:
    """Get OUI updater singleton instance"""
    global _oui_updater
    if _oui_updater is None:
        _oui_updater = OUIUpdater(config, db)
    return _oui_updater
