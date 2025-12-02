"""
Flask API application for Pulse Network Monitor
Provides REST API and minimal web UI
"""

import logging
import json
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

from pulse.storage.db import get_db
from pulse.scheduler.scheduler import get_scheduler
from pulse.scanner.worker import get_orchestrator
from pulse.services.device_recognition import get_recognition_service
from pulse.utils.config import get_config

logger = logging.getLogger(__name__)


def create_app(config=None):
    """Create and configure Flask application"""
    app = Flask(__name__)

    # Load configuration
    cfg = config or get_config()
    app.config['DEBUG'] = cfg.get('api.debug', False)
    app.config['JSON_SORT_KEYS'] = False

    # Enable CORS if configured
    if cfg.get('api.cors.enabled', True):
        origins = cfg.get('api.cors.origins', ['*'])
        CORS(app, origins=origins)

    # Initialize components
    db = get_db()
    scheduler = get_scheduler(cfg, db)
    orchestrator = get_orchestrator(cfg, db)
    recognition = get_recognition_service(cfg, db)

    # Start scheduler
    if not scheduler.is_running:
        scheduler.start()

    # Start orchestrator
    if not orchestrator.worker_pool.executor:
        orchestrator.start()

    # Routes

    @app.route('/')
    def index():
        """Web UI homepage"""
        return render_template_string(HOME_TEMPLATE)

    @app.route('/api/health')
    def health():
        """Health check endpoint"""
        return jsonify({
            'status': 'ok',
            'timestamp': datetime.now().isoformat(),
            'scheduler_running': scheduler.is_running,
            'worker_pool_active': orchestrator.worker_pool.executor is not None
        })

    # Device endpoints

    @app.route('/api/devices')
    def get_devices():
        """Get all devices"""
        active_only = request.args.get('active_only', 'true').lower() == 'true'
        devices = db.get_all_devices(active_only=active_only)

        return jsonify({
            'success': True,
            'count': len(devices),
            'devices': devices
        })

    @app.route('/api/devices/<int:device_id>')
    def get_device(device_id):
        """Get specific device"""
        device = db.get_device(device_id=device_id)

        if not device:
            return jsonify({'success': False, 'error': 'Device not found'}), 404

        # Get device ports
        ports = db.get_device_ports(device_id)
        device['ports'] = ports

        return jsonify({
            'success': True,
            'device': device
        })

    @app.route('/api/devices/<int:device_id>/ports')
    def get_device_ports(device_id):
        """Get ports for a device"""
        ports = db.get_device_ports(device_id)

        return jsonify({
            'success': True,
            'device_id': device_id,
            'count': len(ports),
            'ports': ports
        })

    @app.route('/api/devices/statistics')
    def get_device_statistics():
        """Get device statistics"""
        stats = recognition.get_device_statistics()

        return jsonify({
            'success': True,
            'statistics': stats
        })

    # Scan endpoints

    @app.route('/api/scans/discovery', methods=['POST'])
    def start_discovery_scan():
        """Start discovery scan"""
        data = request.get_json() or {}
        network = data.get('network') or cfg.get('scanner.default_network', '192.168.1.0/24')

        task_id = scheduler.schedule_one_time_scan(network, 'discovery')

        return jsonify({
            'success': True,
            'task_id': task_id,
            'message': f'Discovery scan scheduled for {network}'
        })

    @app.route('/api/scans/quick', methods=['POST'])
    def start_quick_scan():
        """Start quick scan"""
        data = request.get_json() or {}
        target = data.get('target')

        if not target:
            return jsonify({'success': False, 'error': 'Target required'}), 400

        task_id = scheduler.schedule_one_time_scan(target, 'quick')

        return jsonify({
            'success': True,
            'task_id': task_id,
            'message': f'Quick scan scheduled for {target}'
        })

    @app.route('/api/scans/deep', methods=['POST'])
    def start_deep_scan():
        """Start deep scan"""
        data = request.get_json() or {}
        target = data.get('target')

        if not target:
            return jsonify({'success': False, 'error': 'Target required'}), 400

        task_id = scheduler.schedule_one_time_scan(target, 'deep')

        return jsonify({
            'success': True,
            'task_id': task_id,
            'message': f'Deep scan scheduled for {target}'
        })

    @app.route('/api/scans/results')
    def get_scan_results():
        """Get scan results"""
        limit = int(request.args.get('limit', 50))
        results = db.get_scan_results(limit=limit)

        return jsonify({
            'success': True,
            'count': len(results),
            'results': results
        })

    # Task endpoints

    @app.route('/api/tasks')
    def get_tasks():
        """Get scan tasks"""
        limit = int(request.args.get('limit', 50))
        status = request.args.get('status')

        if status == 'pending':
            tasks = db.get_pending_tasks(limit=limit)
        else:
            # Get all tasks (simplified - would need a new DB method for full implementation)
            tasks = db.get_pending_tasks(limit=limit)

        return jsonify({
            'success': True,
            'count': len(tasks),
            'tasks': tasks
        })

    @app.route('/api/tasks/<int:task_id>')
    def get_task(task_id):
        """Get specific task"""
        task = db.get_task(task_id)

        if not task:
            return jsonify({'success': False, 'error': 'Task not found'}), 404

        return jsonify({
            'success': True,
            'task': task
        })

    # Event endpoints

    @app.route('/api/events')
    def get_events():
        """Get events"""
        limit = int(request.args.get('limit', 100))
        severity = request.args.get('severity')

        events = db.get_events(limit=limit, severity=severity)

        return jsonify({
            'success': True,
            'count': len(events),
            'events': events
        })

    # Scheduler endpoints

    @app.route('/api/scheduler/jobs')
    def get_scheduled_jobs():
        """Get scheduled jobs"""
        jobs = scheduler.get_jobs()

        return jsonify({
            'success': True,
            'count': len(jobs),
            'jobs': jobs
        })

    @app.route('/api/scheduler/jobs/<job_id>', methods=['DELETE'])
    def remove_scheduled_job(job_id):
        """Remove scheduled job"""
        success = scheduler.remove_job(job_id)

        if success:
            return jsonify({
                'success': True,
                'message': f'Job {job_id} removed'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to remove job'
            }), 500

    # Configuration endpoints

    @app.route('/api/config')
    def get_config_api():
        """Get configuration"""
        all_config = cfg.get_all()

        return jsonify({
            'success': True,
            'config': all_config
        })

    @app.route('/api/config/<path:key>')
    def get_config_value(key):
        """Get specific configuration value"""
        value = cfg.get(key)

        return jsonify({
            'success': True,
            'key': key,
            'value': value
        })

    # Utility endpoints

    @app.route('/api/suspicious')
    def get_suspicious_devices():
        """Get suspicious devices"""
        suspicious = recognition.identify_suspicious_devices()

        return jsonify({
            'success': True,
            'count': len(suspicious),
            'devices': suspicious
        })

    # Error handlers

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            'success': False,
            'error': 'Not found'
        }), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal error: {error}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

    return app


# Minimal HTML template for web UI
HOME_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Pulse Network Monitor</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #60a5fa; margin-bottom: 2rem; }
        .card {
            background: #1e293b;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid #334155;
        }
        .card h2 { color: #94a3b8; margin-bottom: 1rem; font-size: 1.2rem; }
        .endpoint {
            background: #0f172a;
            padding: 0.75rem;
            margin: 0.5rem 0;
            border-radius: 4px;
            border-left: 3px solid #60a5fa;
        }
        .method {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.75rem;
            margin-right: 0.5rem;
        }
        .get { background: #10b981; color: white; }
        .post { background: #3b82f6; color: white; }
        .delete { background: #ef4444; color: white; }
        code { color: #fbbf24; }
        a { color: #60a5fa; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .status {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            background: #10b981;
            color: white;
            border-radius: 20px;
            font-size: 0.875rem;
            margin-left: 1rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Pulse Network Monitor <span class="status">ONLINE</span></h1>

        <div class="card">
            <h2>📊 Device Management</h2>
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/api/devices</code> - List all devices
            </div>
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/api/devices/{id}</code> - Get device details
            </div>
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/api/devices/{id}/ports</code> - Get device ports
            </div>
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/api/devices/statistics</code> - Device statistics
            </div>
        </div>

        <div class="card">
            <h2>🔎 Scanning</h2>
            <div class="endpoint">
                <span class="method post">POST</span>
                <code>/api/scans/discovery</code> - Start discovery scan
            </div>
            <div class="endpoint">
                <span class="method post">POST</span>
                <code>/api/scans/quick</code> - Start quick port scan
            </div>
            <div class="endpoint">
                <span class="method post">POST</span>
                <code>/api/scans/deep</code> - Start deep scan (OS + services)
            </div>
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/api/scans/results</code> - Get scan results
            </div>
        </div>

        <div class="card">
            <h2>📋 Tasks & Events</h2>
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/api/tasks</code> - List scan tasks
            </div>
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/api/events</code> - List events
            </div>
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/api/suspicious</code> - Get suspicious devices
            </div>
        </div>

        <div class="card">
            <h2>⚙️ Configuration</h2>
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/api/config</code> - Get all configuration
            </div>
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/api/scheduler/jobs</code> - List scheduled jobs
            </div>
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/api/health</code> - Health check
            </div>
        </div>

        <div class="card">
            <h2>📖 Quick Start</h2>
            <p style="line-height: 1.8; color: #cbd5e1;">
                • Start discovery scan: <code>curl -X POST http://localhost:5000/api/scans/discovery</code><br>
                • View devices: <code>curl http://localhost:5000/api/devices</code><br>
                • View events: <code>curl http://localhost:5000/api/events</code><br>
                • Check health: <code>curl http://localhost:5000/api/health</code>
            </p>
        </div>
    </div>
</body>
</html>
"""


def run_app(host=None, port=None, debug=None):
    """Run Flask application"""
    config = get_config()

    if host is None:
        host = config.get('api.host', '0.0.0.0')
    if port is None:
        port = int(config.get('api.port', 5000))
    if debug is None:
        debug = config.get('api.debug', False)

    app = create_app(config)

    logger.info(f"Starting Pulse API server on {host}:{port}")
    app.run(host=host, port=port, debug=debug)
