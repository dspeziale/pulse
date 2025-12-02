-- Pulse Network Monitor Database Schema
-- SQLite Database: instance/pulse.sqlite

-- Tabella dispositivi scoperti
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE,
    mac_address TEXT,
    hostname TEXT,
    vendor TEXT,
    oui TEXT,
    device_type TEXT,
    os_name TEXT,
    os_family TEXT,
    os_version TEXT,
    os_accuracy INTEGER,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'up',
    is_active BOOLEAN DEFAULT 1,
    notes TEXT,
    metadata TEXT
);

CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address);
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);

-- Tabella task di scansione
CREATE TABLE IF NOT EXISTS scan_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_type TEXT NOT NULL,
    target TEXT NOT NULL,
    scan_options TEXT,
    status TEXT DEFAULT 'pending',
    priority INTEGER DEFAULT 5,
    scheduled_at TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error TEXT,
    result_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (result_id) REFERENCES scan_results(id)
);

CREATE INDEX IF NOT EXISTS idx_scan_tasks_status ON scan_tasks(status);
CREATE INDEX IF NOT EXISTS idx_scan_tasks_scheduled ON scan_tasks(scheduled_at);

-- Tabella risultati scansioni
CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER,
    scan_type TEXT NOT NULL,
    target TEXT NOT NULL,
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    duration REAL,
    hosts_up INTEGER DEFAULT 0,
    hosts_down INTEGER DEFAULT 0,
    hosts_total INTEGER DEFAULT 0,
    nmap_command TEXT,
    nmap_version TEXT,
    raw_output TEXT,
    xml_output TEXT,
    summary TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (task_id) REFERENCES scan_tasks(id)
);

CREATE INDEX IF NOT EXISTS idx_scan_results_task ON scan_results(task_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_type ON scan_results(scan_type);

-- Tabella porte aperte per dispositivo
CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    port_number INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    state TEXT NOT NULL,
    service_name TEXT,
    service_product TEXT,
    service_version TEXT,
    service_extrainfo TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
    UNIQUE(device_id, port_number, protocol)
);

CREATE INDEX IF NOT EXISTS idx_ports_device ON ports(device_id);
CREATE INDEX IF NOT EXISTS idx_ports_number ON ports(port_number);

-- Tabella servizi rilevati
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    port_id INTEGER NOT NULL,
    name TEXT,
    product TEXT,
    version TEXT,
    extrainfo TEXT,
    ostype TEXT,
    method TEXT,
    conf INTEGER,
    cpe TEXT,
    scripts_output TEXT,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_services_port ON services(port_id);
CREATE INDEX IF NOT EXISTS idx_services_name ON services(name);

-- Tabella storico dispositivi
CREATE TABLE IF NOT EXISTS device_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    change_type TEXT NOT NULL,
    field_name TEXT,
    old_value TEXT,
    new_value TEXT,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_device_history_device ON device_history(device_id);
CREATE INDEX IF NOT EXISTS idx_device_history_date ON device_history(changed_at);

-- Tabella eventi e alert
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    severity TEXT DEFAULT 'info',
    device_id INTEGER,
    title TEXT NOT NULL,
    description TEXT,
    metadata TEXT,
    acknowledged BOOLEAN DEFAULT 0,
    acknowledged_at TIMESTAMP,
    acknowledged_by TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_device ON events(device_id);
CREATE INDEX IF NOT EXISTS idx_events_date ON events(created_at);

-- Tabella configurazioni runtime
CREATE TABLE IF NOT EXISTS configuration (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    value TEXT,
    value_type TEXT DEFAULT 'string',
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabella OUI (Organizationally Unique Identifier) cache
CREATE TABLE IF NOT EXISTS oui_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    oui TEXT NOT NULL UNIQUE,
    vendor TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_oui_cache_oui ON oui_cache(oui);

-- Tabella statistiche
CREATE TABLE IF NOT EXISTS statistics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stat_type TEXT NOT NULL,
    stat_key TEXT NOT NULL,
    stat_value REAL NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(stat_type, stat_key, timestamp)
);

CREATE INDEX IF NOT EXISTS idx_statistics_type ON statistics(stat_type);
CREATE INDEX IF NOT EXISTS idx_statistics_timestamp ON statistics(timestamp);

-- Inserimento configurazioni di default
INSERT OR IGNORE INTO configuration (key, value, value_type, description) VALUES
    ('scanner.default_network', '192.168.1.0/24', 'string', 'Default network range for scanning'),
    ('scanner.max_workers', '4', 'integer', 'Maximum number of concurrent scan workers'),
    ('scanner.discovery_interval', '300', 'integer', 'Discovery scan interval in seconds'),
    ('scanner.deep_scan_interval', '3600', 'integer', 'Deep scan interval in seconds'),
    ('oui.update_url', 'https://standards-oui.ieee.org/oui/oui.txt', 'string', 'OUI database update URL'),
    ('oui.last_update', '', 'string', 'Last OUI database update timestamp'),
    ('alerts.enabled', 'true', 'boolean', 'Enable alert notifications'),
    ('alerts.webhook_url', '', 'string', 'Webhook URL for alerts'),
    ('api.host', '0.0.0.0', 'string', 'API server host'),
    ('api.port', '5000', 'integer', 'API server port'),
    ('api.debug', 'false', 'boolean', 'API debug mode');
