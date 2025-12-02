"""
Worker pool for parallel scan execution
Windows-compatible version using ThreadPoolExecutor
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Callable, Optional
from datetime import datetime

from pulse.scanner.engine import create_scanner, ScanType
from pulse.parser.nmap_parser import create_parser
from pulse.storage.db import get_db
from pulse.utils.config import get_config

logger = logging.getLogger(__name__)


class ScanWorkerPool:
    """Worker pool for managing parallel scan execution (Windows-compatible)"""

    def __init__(self, config=None):
        """Initialize worker pool"""
        self.config = config or get_config()
        self.max_workers = self.config.get('scanner.workers.max_workers', 4)
        self.executor = None
        self.active_tasks = {}

        logger.info(f"Worker pool initialized with {self.max_workers} workers (ThreadPoolExecutor)")

    def start(self):
        """Start the worker pool"""
        if self.executor is None:
            # Use ThreadPoolExecutor for Windows compatibility
            # Threads work well for I/O bound operations like running nmap subprocesses
            self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
            logger.info("Worker pool started (ThreadPoolExecutor)")

    def _scan_worker(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Worker method for executing a scan task
        Runs in a separate thread (Windows-compatible)

        Args:
            task_data: Task data dictionary

        Returns:
            Result dictionary
        """
        task_id = task_data.get('id')
        target = task_data.get('target')
        task_type = task_data.get('task_type')
        scan_options = task_data.get('scan_options')

        logger.info(f"Worker starting task {task_id}: {task_type} scan of {target}")

        try:
            # Create scanner instance (thread-safe)
            scanner = create_scanner(self.config)

            # Execute scan
            timeout = self.config.get('scanner.workers.timeout', 600)

            if task_type == 'discovery':
                result = scanner.discovery_scan(target, timeout=timeout)
            elif task_type == 'quick':
                result = scanner.quick_scan(target, timeout=timeout)
            elif task_type == 'deep':
                result = scanner.deep_scan(target, timeout=timeout)
            elif task_type == 'full':
                result = scanner.full_scan(target, timeout=timeout)
            elif task_type == 'custom':
                result = scanner.scan(target, ScanType.CUSTOM, options=scan_options, timeout=timeout)
            else:
                return {
                    'task_id': task_id,
                    'success': False,
                    'error': f'Unknown task type: {task_type}'
                }

            # Parse results if successful
            if result.get('success') and result.get('xml_output'):
                parser = create_parser()
                parsed_data = parser.parse_xml(result['xml_output'])
                result['parsed_data'] = parsed_data

                # Extract devices
                devices = parser.extract_devices(parsed_data)
                result['devices'] = devices

            result['task_id'] = task_id
            return result

        except Exception as e:
            logger.error(f"Worker error for task {task_id}: {e}", exc_info=True)
            return {
                'task_id': task_id,
                'success': False,
                'error': str(e)
            }

    def stop(self, wait: bool = True):
        """Stop the worker pool"""
        if self.executor:
            self.executor.shutdown(wait=wait)
            self.executor = None
            logger.info("Worker pool stopped")

    def submit_task(self, task_data: Dict[str, Any], callback: Callable = None) -> Any:
        """
        Submit a task to the worker pool

        Args:
            task_data: Task data dictionary
            callback: Optional callback function to call when task completes

        Returns:
            Future object
        """
        if self.executor is None:
            self.start()

        task_id = task_data.get('id')
        # Submit the worker method (thread-safe, Windows-compatible)
        future = self.executor.submit(self._scan_worker, task_data)

        if callback:
            future.add_done_callback(lambda f: callback(f.result()))

        self.active_tasks[task_id] = future
        logger.info(f"Task {task_id} submitted to worker pool")

        return future

    def submit_tasks(self, tasks: List[Dict[str, Any]], callback: Callable = None) -> List[Any]:
        """
        Submit multiple tasks to the worker pool

        Args:
            tasks: List of task data dictionaries
            callback: Optional callback function

        Returns:
            List of future objects
        """
        futures = []
        for task in tasks:
            future = self.submit_task(task, callback)
            futures.append(future)

        return futures

    def get_task_result(self, task_id: int, timeout: float = None) -> Optional[Dict[str, Any]]:
        """
        Get result of a specific task

        Args:
            task_id: Task ID
            timeout: Timeout in seconds

        Returns:
            Result dictionary or None
        """
        if task_id in self.active_tasks:
            future = self.active_tasks[task_id]
            try:
                result = future.result(timeout=timeout)
                del self.active_tasks[task_id]
                return result
            except Exception as e:
                logger.error(f"Error getting result for task {task_id}: {e}")
                return None
        return None

    def wait_for_completion(self, timeout: float = None) -> List[Dict[str, Any]]:
        """
        Wait for all active tasks to complete

        Args:
            timeout: Timeout in seconds

        Returns:
            List of results
        """
        results = []
        futures = list(self.active_tasks.values())

        for future in as_completed(futures, timeout=timeout):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                logger.error(f"Error waiting for task completion: {e}")

        self.active_tasks.clear()
        return results

    def get_active_task_count(self) -> int:
        """Get number of active tasks"""
        return len(self.active_tasks)

    def cancel_task(self, task_id: int) -> bool:
        """
        Cancel a specific task

        Args:
            task_id: Task ID

        Returns:
            True if cancelled, False otherwise
        """
        if task_id in self.active_tasks:
            future = self.active_tasks[task_id]
            cancelled = future.cancel()
            if cancelled:
                del self.active_tasks[task_id]
                logger.info(f"Task {task_id} cancelled")
            return cancelled
        return False

    def cancel_all_tasks(self) -> int:
        """
        Cancel all active tasks

        Returns:
            Number of tasks cancelled
        """
        count = 0
        for task_id in list(self.active_tasks.keys()):
            if self.cancel_task(task_id):
                count += 1

        logger.info(f"Cancelled {count} tasks")
        return count


class ScanOrchestrator:
    """Orchestrates scan execution and result processing"""

    def __init__(self, config=None, db=None):
        """Initialize orchestrator"""
        self.config = config or get_config()
        self.db = db or get_db()
        self.worker_pool = ScanWorkerPool(config)

    def start(self):
        """Start the orchestrator"""
        self.worker_pool.start()
        logger.info("Scan orchestrator started")

    def stop(self):
        """Stop the orchestrator"""
        self.worker_pool.stop()
        logger.info("Scan orchestrator stopped")

    def execute_task(self, task_id: int) -> Dict[str, Any]:
        """
        Execute a scan task

        Args:
            task_id: Task ID from database

        Returns:
            Scan result dictionary
        """
        # Get task from database
        task_data = self.db.get_task(task_id)
        if not task_data:
            logger.error(f"Task {task_id} not found")
            return {'success': False, 'error': 'Task not found'}

        # Update task status to running
        self.db.update_task_status(task_id, 'running')

        # Submit to worker pool
        future = self.worker_pool.submit_task(dict(task_data))

        try:
            # Wait for result
            result = future.result()

            # Process result
            self._process_scan_result(result)

            # Update task status
            if result.get('success'):
                self.db.update_task_status(task_id, 'completed')
            else:
                self.db.update_task_status(task_id, 'failed', result.get('error'))

            return result

        except Exception as e:
            logger.error(f"Error executing task {task_id}: {e}")
            self.db.update_task_status(task_id, 'failed', str(e))
            return {'success': False, 'error': str(e)}

    def execute_pending_tasks(self, limit: int = 10):
        """
        Execute pending tasks from database

        Args:
            limit: Maximum number of tasks to execute
        """
        pending_tasks = self.db.get_pending_tasks(limit)

        if not pending_tasks:
            logger.debug("No pending tasks")
            return

        logger.info(f"Executing {len(pending_tasks)} pending tasks")

        futures = []
        for task in pending_tasks:
            task_id = task['id']
            self.db.update_task_status(task_id, 'running')

            future = self.worker_pool.submit_task(
                dict(task),
                callback=lambda result: self._task_completed_callback(result)
            )
            futures.append((task_id, future))

        # Monitor completion (non-blocking)
        return futures

    def _task_completed_callback(self, result: Dict[str, Any]):
        """Callback when a task completes"""
        task_id = result.get('task_id')
        logger.info(f"Task {task_id} completed")

        # Process result
        self._process_scan_result(result)

        # Update task status
        if result.get('success'):
            self.db.update_task_status(task_id, 'completed')
        else:
            self.db.update_task_status(task_id, 'failed', result.get('error'))

    def _process_scan_result(self, result: Dict[str, Any]):
        """Process scan result and update database"""
        task_id = result.get('task_id')

        try:
            logger.info(f"📊 Processing scan result for task {task_id}")

            # Check if scan was successful
            if not result.get('success'):
                logger.warning(f"⚠️  Task {task_id} failed: {result.get('error')}")
                return

            # Save scan result
            logger.debug(f"💾 Saving scan result for task {task_id}")
            result_id = self.db.save_scan_result({
                'task_id': task_id,
                'scan_type': result.get('scan_type'),
                'target': result.get('target'),
                'start_time': result.get('start_time'),
                'end_time': result.get('end_time'),
                'duration': result.get('duration'),
                'hosts_up': result.get('parsed_data', {}).get('hosts_up', 0),
                'hosts_down': result.get('parsed_data', {}).get('hosts_down', 0),
                'hosts_total': result.get('parsed_data', {}).get('hosts_total', 0),
                'nmap_command': result.get('command'),
                'nmap_version': result.get('nmap_version'),
                'raw_output': result.get('stdout'),
                'xml_output': result.get('xml_output'),
                'summary': f"Scanned {result.get('target')} - {result.get('parsed_data', {}).get('hosts_up', 0)} hosts up"
            })
            logger.info(f"✅ Scan result saved with ID: {result_id}")

            # Process discovered devices
            devices = result.get('devices', [])
            logger.info(f"🔍 Processing {len(devices)} discovered devices")

            for idx, device_data in enumerate(devices, 1):
                try:
                    ip_address = device_data.get('ip_address')
                    logger.debug(f"📡 Processing device {idx}/{len(devices)}: {ip_address}")

                    device_id = self.db.add_device(device_data)
                    logger.debug(f"✅ Device {ip_address} saved with ID: {device_id}")

                    # Add ports
                    ports = device_data.get('metadata', {}).get('ports', [])
                    if ports:
                        logger.debug(f"🔌 Adding {len(ports)} ports for device {ip_address}")
                        for port in ports:
                            try:
                                self.db.add_port({
                                    'device_id': device_id,
                                    'port_number': int(port.get('port', 0)),
                                    'protocol': port.get('protocol', 'tcp'),
                                    'state': port.get('state', 'unknown'),
                                    'service_name': port.get('service', {}).get('name'),
                                    'service_product': port.get('service', {}).get('product'),
                                    'service_version': port.get('service', {}).get('version'),
                                    'service_extrainfo': port.get('service', {}).get('extrainfo')
                                })
                            except Exception as port_error:
                                logger.error(f"❌ Error adding port {port.get('port')} for device {ip_address}: {port_error}")

                    # Create event for new device
                    self.db.create_event({
                        'event_type': 'device_discovered',
                        'severity': 'info',
                        'device_id': device_id,
                        'title': f"Device discovered: {ip_address}",
                        'description': f"New device found - {device_data.get('hostname') or ip_address}"
                    })
                    logger.debug(f"📢 Event created for device {ip_address}")

                except Exception as device_error:
                    logger.error(f"❌ Error processing device {device_data.get('ip_address')}: {device_error}", exc_info=True)
                    continue

            logger.info(f"✅ Successfully processed {len(devices)} devices from scan result")

        except Exception as e:
            logger.error(f"❌ Error processing scan result for task {task_id}: {e}", exc_info=True)


# Global orchestrator instance
_orchestrator = None


def get_orchestrator(config=None, db=None) -> ScanOrchestrator:
    """Get orchestrator singleton instance"""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = ScanOrchestrator(config, db)
    return _orchestrator
