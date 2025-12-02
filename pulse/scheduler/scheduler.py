"""
Scheduler for automated scan tasks using APScheduler
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger

from pulse.storage.db import get_db
from pulse.scanner.worker import get_orchestrator
from pulse.utils.config import get_config

logger = logging.getLogger(__name__)


class ScanScheduler:
    """Scheduler for automated network scans"""

    def __init__(self, config=None, db=None):
        """Initialize scheduler"""
        self.config = config or get_config()
        self.db = db or get_db()
        self.orchestrator = get_orchestrator(config, db)

        # Configure job stores
        jobstores = {}
        if self.config.get('scheduler.jobstore') == 'sqlite':
            jobstore_path = self.config.get('scheduler.jobstore_path', 'instance/jobs.sqlite')
            jobstores['default'] = SQLAlchemyJobStore(url=f'sqlite:///{jobstore_path}')

        # Configure executors
        executors = {
            'default': ThreadPoolExecutor(10)
        }

        # Configure job defaults
        job_defaults = {
            'coalesce': self.config.get('scheduler.coalesce', True),
            'max_instances': self.config.get('scheduler.max_instances', 1),
            'misfire_grace_time': 300
        }

        # Create scheduler
        self.scheduler = BackgroundScheduler(
            jobstores=jobstores,
            executors=executors,
            job_defaults=job_defaults
        )

        self.is_running = False

    def start(self):
        """Start the scheduler"""
        if not self.is_running:
            self.scheduler.start()
            self.is_running = True
            self._setup_default_jobs()
            logger.info("Scheduler started")

    def stop(self):
        """Stop the scheduler"""
        if self.is_running:
            self.scheduler.shutdown()
            self.is_running = False
            logger.info("Scheduler stopped")

    def _setup_default_jobs(self):
        """Setup default scheduled jobs"""
        # Discovery scan job
        discovery_interval = self.config.get('scanner.intervals.discovery', 300)
        if discovery_interval > 0:
            self.schedule_recurring_discovery(
                interval_seconds=discovery_interval,
                job_id='recurring_discovery'
            )

        # Process pending tasks job
        self.scheduler.add_job(
            self._process_pending_tasks,
            trigger=IntervalTrigger(seconds=30),
            id='process_pending_tasks',
            replace_existing=True
        )

        logger.info("Default scheduled jobs configured")

    def schedule_recurring_discovery(
        self,
        network: str = None,
        interval_seconds: int = 300,
        job_id: str = 'discovery_scan'
    ):
        """
        Schedule recurring network discovery scan

        Args:
            network: Network range to scan (e.g., '192.168.1.0/24')
            interval_seconds: Interval between scans in seconds
            job_id: Unique job ID
        """
        if network is None:
            network = self.config.get('scanner.default_network', '192.168.1.0/24')

        self.scheduler.add_job(
            self._run_discovery_scan,
            trigger=IntervalTrigger(seconds=interval_seconds),
            args=[network],
            id=job_id,
            replace_existing=True
        )

        logger.info(f"Scheduled recurring discovery scan for {network} every {interval_seconds}s")

    def schedule_recurring_scan(
        self,
        target: str,
        scan_type: str,
        interval_seconds: int,
        job_id: str = None
    ):
        """
        Schedule recurring scan for a specific target

        Args:
            target: Target IP or network
            scan_type: Type of scan (quick, deep, full)
            interval_seconds: Interval between scans
            job_id: Unique job ID
        """
        if job_id is None:
            job_id = f"scan_{scan_type}_{target.replace('/', '_')}"

        self.scheduler.add_job(
            self._run_scan,
            trigger=IntervalTrigger(seconds=interval_seconds),
            args=[target, scan_type],
            id=job_id,
            replace_existing=True
        )

        logger.info(f"Scheduled recurring {scan_type} scan for {target} every {interval_seconds}s")

    def schedule_cron_scan(
        self,
        target: str,
        scan_type: str,
        cron_expression: Dict[str, Any],
        job_id: str = None
    ):
        """
        Schedule scan using cron expression

        Args:
            target: Target IP or network
            scan_type: Type of scan
            cron_expression: Cron expression dict (hour, minute, day, etc.)
            job_id: Unique job ID
        """
        if job_id is None:
            job_id = f"cron_scan_{scan_type}_{target.replace('/', '_')}"

        self.scheduler.add_job(
            self._run_scan,
            trigger=CronTrigger(**cron_expression),
            args=[target, scan_type],
            id=job_id,
            replace_existing=True
        )

        logger.info(f"Scheduled cron {scan_type} scan for {target}")

    def schedule_one_time_scan(
        self,
        target: str,
        scan_type: str,
        run_date: datetime = None
    ) -> int:
        """
        Schedule one-time scan

        Args:
            target: Target IP or network
            scan_type: Type of scan
            run_date: When to run (defaults to now)

        Returns:
            Task ID
        """
        if run_date is None:
            run_date = datetime.now()

        # Create task in database
        task_id = self.db.create_scan_task({
            'task_type': scan_type,
            'target': target,
            'status': 'pending',
            'scheduled_at': run_date.isoformat()
        })

        logger.info(f"Scheduled one-time {scan_type} scan for {target} at {run_date}")
        return task_id

    def remove_job(self, job_id: str) -> bool:
        """
        Remove a scheduled job

        Args:
            job_id: Job ID to remove

        Returns:
            True if removed, False otherwise
        """
        try:
            self.scheduler.remove_job(job_id)
            logger.info(f"Removed scheduled job: {job_id}")
            return True
        except Exception as e:
            logger.error(f"Error removing job {job_id}: {e}")
            return False

    def get_jobs(self) -> List[Dict[str, Any]]:
        """Get all scheduled jobs"""
        jobs = []
        for job in self.scheduler.get_jobs():
            jobs.append({
                'id': job.id,
                'name': job.name,
                'trigger': str(job.trigger),
                'next_run_time': job.next_run_time.isoformat() if job.next_run_time else None,
                'args': job.args,
                'kwargs': job.kwargs
            })
        return jobs

    def _run_discovery_scan(self, network: str):
        """Run discovery scan (called by scheduler)"""
        logger.info(f"Running scheduled discovery scan for {network}")

        try:
            # Create task
            task_id = self.db.create_scan_task({
                'task_type': 'discovery',
                'target': network,
                'status': 'pending'
            })

            # Execute immediately
            self.orchestrator.execute_task(task_id)

        except Exception as e:
            logger.error(f"Error running discovery scan: {e}", exc_info=True)

    def _run_scan(self, target: str, scan_type: str):
        """Run scan (called by scheduler)"""
        logger.info(f"Running scheduled {scan_type} scan for {target}")

        try:
            # Create task
            task_id = self.db.create_scan_task({
                'task_type': scan_type,
                'target': target,
                'status': 'pending'
            })

            # Execute immediately
            self.orchestrator.execute_task(task_id)

        except Exception as e:
            logger.error(f"Error running {scan_type} scan: {e}", exc_info=True)

    def _process_pending_tasks(self):
        """Process pending tasks from database"""
        try:
            # Get pending tasks
            pending_tasks = self.db.get_pending_tasks(limit=10)

            if not pending_tasks:
                return

            logger.debug(f"Processing {len(pending_tasks)} pending tasks")

            # Execute tasks
            for task in pending_tasks:
                try:
                    self.orchestrator.execute_task(task['id'])
                except Exception as e:
                    logger.error(f"Error executing task {task['id']}: {e}")
                    self.db.update_task_status(task['id'], 'failed', str(e))

        except Exception as e:
            logger.error(f"Error processing pending tasks: {e}", exc_info=True)

    def pause_job(self, job_id: str) -> bool:
        """Pause a scheduled job"""
        try:
            self.scheduler.pause_job(job_id)
            logger.info(f"Paused job: {job_id}")
            return True
        except Exception as e:
            logger.error(f"Error pausing job {job_id}: {e}")
            return False

    def resume_job(self, job_id: str) -> bool:
        """Resume a paused job"""
        try:
            self.scheduler.resume_job(job_id)
            logger.info(f"Resumed job: {job_id}")
            return True
        except Exception as e:
            logger.error(f"Error resuming job {job_id}: {e}")
            return False

    def reschedule_job(
        self,
        job_id: str,
        trigger_type: str = 'interval',
        **trigger_args
    ) -> bool:
        """
        Reschedule a job with new trigger

        Args:
            job_id: Job ID to reschedule
            trigger_type: Type of trigger ('interval', 'cron', 'date')
            **trigger_args: Trigger-specific arguments
        """
        try:
            if trigger_type == 'interval':
                trigger = IntervalTrigger(**trigger_args)
            elif trigger_type == 'cron':
                trigger = CronTrigger(**trigger_args)
            else:
                logger.error(f"Unknown trigger type: {trigger_type}")
                return False

            self.scheduler.reschedule_job(job_id, trigger=trigger)
            logger.info(f"Rescheduled job: {job_id}")
            return True

        except Exception as e:
            logger.error(f"Error rescheduling job {job_id}: {e}")
            return False


# Global scheduler instance
_scheduler = None


def get_scheduler(config=None, db=None) -> ScanScheduler:
    """Get scheduler singleton instance"""
    global _scheduler
    if _scheduler is None:
        _scheduler = ScanScheduler(config, db)
    return _scheduler
