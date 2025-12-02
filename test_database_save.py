"""
Test script per verificare il salvataggio dei risultati nel database
"""

import sys
import os
import time
import logging

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pulse.storage.db import get_db
from pulse.scheduler.scheduler import get_scheduler
from pulse.scanner.worker import get_orchestrator
from pulse.utils.config import get_config

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def test_scan_and_save():
    """Test scanning and saving to database"""
    logger.info("=" * 60)
    logger.info("TEST: Scanning and Database Save")
    logger.info("=" * 60)

    # Initialize components
    config = get_config()
    db = get_db()
    scheduler = get_scheduler(config, db)

    logger.info("✅ Components initialized")

    # Create a test scan task
    logger.info("📋 Creating test scan task...")
    task_id = db.create_scan_task({
        'task_type': 'discovery',
        'target': '127.0.0.1',  # Scan localhost
        'status': 'pending',
        'priority': 10
    })
    logger.info(f"✅ Task created with ID: {task_id}")

    # Execute the task
    logger.info(f"🚀 Executing task {task_id}...")
    orchestrator = get_orchestrator(config, db)
    result = orchestrator.execute_task(task_id)

    if result.get('success'):
        logger.info("✅ Task executed successfully")
    else:
        logger.error(f"❌ Task failed: {result.get('error')}")
        return False

    # Wait a bit for database writes
    time.sleep(2)

    # Verify data was saved
    logger.info("=" * 60)
    logger.info("VERIFICATION: Checking Database")
    logger.info("=" * 60)

    # Check scan results
    logger.info("📊 Checking scan results...")
    scan_results = db.get_scan_results(limit=10)
    logger.info(f"Found {len(scan_results)} scan results")
    for sr in scan_results:
        logger.info(f"  - Result ID {sr['id']}: {sr['target']} ({sr['scan_type']})")

    # Check devices
    logger.info("🖥️  Checking devices...")
    devices = db.get_all_devices(active_only=False)
    logger.info(f"Found {len(devices)} devices")
    for device in devices:
        logger.info(f"  - Device {device['id']}: {device['ip_address']} ({device.get('hostname', 'unknown')})")

        # Check ports for this device
        ports = db.get_device_ports(device['id'])
        logger.info(f"    └─ {len(ports)} ports")
        for port in ports[:5]:  # Show first 5 ports
            logger.info(f"       └─ Port {port['port_number']}/{port['protocol']} ({port['state']}) - {port.get('service_name', 'unknown')}")

    # Check events
    logger.info("📢 Checking events...")
    events = db.get_events(limit=10)
    logger.info(f"Found {len(events)} events")
    for event in events:
        logger.info(f"  - Event {event['id']}: {event['title']} ({event['severity']})")

    # Check tasks
    logger.info("📋 Checking tasks...")
    task = db.get_task(task_id)
    if task:
        logger.info(f"Task {task_id} status: {task['status']}")

    logger.info("=" * 60)
    if len(scan_results) > 0 and len(devices) > 0:
        logger.info("✅ TEST PASSED: Data was saved to database!")
    else:
        logger.error("❌ TEST FAILED: Data was NOT saved to database!")
        return False

    return True


if __name__ == '__main__':
    try:
        success = test_scan_and_save()
        sys.exit(0 if success else 1)
    except Exception as e:
        logger.error(f"❌ Test error: {e}", exc_info=True)
        sys.exit(1)
