"""
Database management module for Pulse Network Monitor
Handles all SQLite database operations
"""

import sqlite3
import os
import json
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager
import threading


class Database:
    """Database manager for Pulse Network Monitor"""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, db_path: str = None):
        """Singleton pattern implementation"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, db_path: str = None):
        """Initialize database connection"""
        if not hasattr(self, 'initialized'):
            self.db_path = db_path or 'instance/pulse.sqlite'
            self.local = threading.local()
            self._ensure_db_directory()
            self.initialize_schema()
            self.initialized = True

    def _ensure_db_directory(self):
        """Ensure database directory exists"""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

    def get_connection(self) -> sqlite3.Connection:
        """Get thread-local database connection"""
        if not hasattr(self.local, 'connection') or self.local.connection is None:
            self.local.connection = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=30.0
            )
            self.local.connection.row_factory = sqlite3.Row
            # Enable foreign keys
            self.local.connection.execute("PRAGMA foreign_keys = ON")
        return self.local.connection

    @contextmanager
    def get_cursor(self):
        """Context manager for database cursor"""
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()

    def initialize_schema(self):
        """Initialize database schema from SQL file"""
        schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')

        if not os.path.exists(schema_path):
            raise FileNotFoundError(f"Schema file not found: {schema_path}")

        with open(schema_path, 'r') as f:
            schema_sql = f.read()

        with self.get_cursor() as cursor:
            cursor.executescript(schema_sql)

    def close(self):
        """Close database connection"""
        if hasattr(self.local, 'connection') and self.local.connection:
            self.local.connection.close()
            self.local.connection = None

    # Device operations

    def add_device(self, device_data: Dict[str, Any]) -> int:
        """Add or update a device"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO devices (
                    ip_address, mac_address, hostname, vendor, oui,
                    device_type, os_name, os_family, os_version, os_accuracy,
                    status, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    mac_address = excluded.mac_address,
                    hostname = excluded.hostname,
                    vendor = excluded.vendor,
                    oui = excluded.oui,
                    device_type = excluded.device_type,
                    os_name = excluded.os_name,
                    os_family = excluded.os_family,
                    os_version = excluded.os_version,
                    os_accuracy = excluded.os_accuracy,
                    last_seen = CURRENT_TIMESTAMP,
                    status = excluded.status,
                    metadata = excluded.metadata
            """, (
                device_data.get('ip_address'),
                device_data.get('mac_address'),
                device_data.get('hostname'),
                device_data.get('vendor'),
                device_data.get('oui'),
                device_data.get('device_type'),
                device_data.get('os_name'),
                device_data.get('os_family'),
                device_data.get('os_version'),
                device_data.get('os_accuracy'),
                device_data.get('status', 'up'),
                json.dumps(device_data.get('metadata', {}))
            ))
            return cursor.lastrowid

    def get_device(self, device_id: int = None, ip_address: str = None) -> Optional[Dict]:
        """Get device by ID or IP address"""
        with self.get_cursor() as cursor:
            if device_id:
                cursor.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
            elif ip_address:
                cursor.execute("SELECT * FROM devices WHERE ip_address = ?", (ip_address,))
            else:
                return None

            row = cursor.fetchone()
            return dict(row) if row else None

    def get_all_devices(self, active_only: bool = True) -> List[Dict]:
        """Get all devices"""
        with self.get_cursor() as cursor:
            if active_only:
                cursor.execute("SELECT * FROM devices WHERE is_active = 1 ORDER BY last_seen DESC")
            else:
                cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")

            return [dict(row) for row in cursor.fetchall()]

    def update_device_status(self, device_id: int, status: str):
        """Update device status"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                UPDATE devices
                SET status = ?, last_seen = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (status, device_id))

    # Scan task operations

    def create_scan_task(self, task_data: Dict[str, Any]) -> int:
        """Create a new scan task"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO scan_tasks (
                    task_type, target, scan_options, status,
                    priority, scheduled_at
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                task_data.get('task_type'),
                task_data.get('target'),
                json.dumps(task_data.get('scan_options', {})),
                task_data.get('status', 'pending'),
                task_data.get('priority', 5),
                task_data.get('scheduled_at')
            ))
            return cursor.lastrowid

    def get_pending_tasks(self, limit: int = 10) -> List[Dict]:
        """Get pending scan tasks"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                SELECT * FROM scan_tasks
                WHERE status = 'pending'
                AND (scheduled_at IS NULL OR scheduled_at <= CURRENT_TIMESTAMP)
                ORDER BY priority DESC, created_at ASC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def update_task_status(self, task_id: int, status: str, error: str = None):
        """Update scan task status"""
        with self.get_cursor() as cursor:
            if status == 'running':
                cursor.execute("""
                    UPDATE scan_tasks
                    SET status = ?, started_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (status, task_id))
            elif status in ['completed', 'failed']:
                cursor.execute("""
                    UPDATE scan_tasks
                    SET status = ?, completed_at = CURRENT_TIMESTAMP,
                        updated_at = CURRENT_TIMESTAMP, error = ?
                    WHERE id = ?
                """, (status, error, task_id))
            else:
                cursor.execute("""
                    UPDATE scan_tasks
                    SET status = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (status, task_id))

    def get_task(self, task_id: int) -> Optional[Dict]:
        """Get scan task by ID"""
        with self.get_cursor() as cursor:
            cursor.execute("SELECT * FROM scan_tasks WHERE id = ?", (task_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    # Scan results operations

    def save_scan_result(self, result_data: Dict[str, Any]) -> int:
        """Save scan result"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO scan_results (
                    task_id, scan_type, target, start_time, end_time,
                    duration, hosts_up, hosts_down, hosts_total,
                    nmap_command, nmap_version, raw_output, xml_output, summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result_data.get('task_id'),
                result_data.get('scan_type'),
                result_data.get('target'),
                result_data.get('start_time'),
                result_data.get('end_time'),
                result_data.get('duration'),
                result_data.get('hosts_up', 0),
                result_data.get('hosts_down', 0),
                result_data.get('hosts_total', 0),
                result_data.get('nmap_command'),
                result_data.get('nmap_version'),
                result_data.get('raw_output'),
                result_data.get('xml_output'),
                result_data.get('summary')
            ))
            return cursor.lastrowid

    def get_scan_results(self, limit: int = 50) -> List[Dict]:
        """Get recent scan results"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                SELECT * FROM scan_results
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    # Port operations

    def add_port(self, port_data: Dict[str, Any]) -> int:
        """Add or update port information"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO ports (
                    device_id, port_number, protocol, state,
                    service_name, service_product, service_version, service_extrainfo
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id, port_number, protocol) DO UPDATE SET
                    state = excluded.state,
                    service_name = excluded.service_name,
                    service_product = excluded.service_product,
                    service_version = excluded.service_version,
                    service_extrainfo = excluded.service_extrainfo,
                    last_seen = CURRENT_TIMESTAMP
            """, (
                port_data.get('device_id'),
                port_data.get('port_number'),
                port_data.get('protocol', 'tcp'),
                port_data.get('state'),
                port_data.get('service_name'),
                port_data.get('service_product'),
                port_data.get('service_version'),
                port_data.get('service_extrainfo')
            ))
            return cursor.lastrowid

    def get_device_ports(self, device_id: int) -> List[Dict]:
        """Get all ports for a device"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                SELECT * FROM ports
                WHERE device_id = ?
                ORDER BY port_number
            """, (device_id,))
            return [dict(row) for row in cursor.fetchall()]

    # Event operations

    def create_event(self, event_data: Dict[str, Any]) -> int:
        """Create a new event"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO events (
                    event_type, severity, device_id, title,
                    description, metadata
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                event_data.get('event_type'),
                event_data.get('severity', 'info'),
                event_data.get('device_id'),
                event_data.get('title'),
                event_data.get('description'),
                json.dumps(event_data.get('metadata', {}))
            ))
            return cursor.lastrowid

    def get_events(self, limit: int = 100, severity: str = None) -> List[Dict]:
        """Get recent events"""
        with self.get_cursor() as cursor:
            if severity:
                cursor.execute("""
                    SELECT * FROM events
                    WHERE severity = ?
                    ORDER BY created_at DESC
                    LIMIT ?
                """, (severity, limit))
            else:
                cursor.execute("""
                    SELECT * FROM events
                    ORDER BY created_at DESC
                    LIMIT ?
                """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    # Configuration operations

    def get_config(self, key: str) -> Optional[str]:
        """Get configuration value"""
        with self.get_cursor() as cursor:
            cursor.execute("SELECT value FROM configuration WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row['value'] if row else None

    def set_config(self, key: str, value: str, description: str = None):
        """Set configuration value"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO configuration (key, value, description)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = CURRENT_TIMESTAMP
            """, (key, value, description))

    def get_all_config(self) -> Dict[str, str]:
        """Get all configuration values"""
        with self.get_cursor() as cursor:
            cursor.execute("SELECT key, value FROM configuration")
            return {row['key']: row['value'] for row in cursor.fetchall()}

    # OUI cache operations

    def get_oui_vendor(self, oui: str) -> Optional[str]:
        """Get vendor from OUI cache"""
        with self.get_cursor() as cursor:
            cursor.execute("SELECT vendor FROM oui_cache WHERE oui = ?", (oui.upper(),))
            row = cursor.fetchone()
            return row['vendor'] if row else None

    def add_oui(self, oui: str, vendor: str):
        """Add OUI to cache"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO oui_cache (oui, vendor)
                VALUES (?, ?)
                ON CONFLICT(oui) DO UPDATE SET
                    vendor = excluded.vendor,
                    updated_at = CURRENT_TIMESTAMP
            """, (oui.upper(), vendor))

    def bulk_insert_oui(self, oui_data: List[Tuple[str, str]]):
        """Bulk insert OUI data"""
        with self.get_cursor() as cursor:
            cursor.executemany("""
                INSERT OR REPLACE INTO oui_cache (oui, vendor, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            """, oui_data)

    # Statistics operations

    def record_statistic(self, stat_type: str, stat_key: str, stat_value: float):
        """Record a statistic"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO statistics (stat_type, stat_key, stat_value)
                VALUES (?, ?, ?)
            """, (stat_type, stat_key, stat_value))

    def get_statistics(self, stat_type: str, limit: int = 100) -> List[Dict]:
        """Get statistics by type"""
        with self.get_cursor() as cursor:
            cursor.execute("""
                SELECT * FROM statistics
                WHERE stat_type = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (stat_type, limit))
            return [dict(row) for row in cursor.fetchall()]


# Singleton instance
_db_instance = None

def get_db(db_path: str = None) -> Database:
    """Get database singleton instance"""
    global _db_instance
    if _db_instance is None:
        _db_instance = Database(db_path)
    return _db_instance
