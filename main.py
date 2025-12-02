#!/usr/bin/env python3
"""
Pulse Network Monitor - Main Entry Point
Network discovery and monitoring system using Python, SQLite, and Nmap
"""

import sys
import os
import logging
import argparse
from logging.handlers import RotatingFileHandler

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pulse.utils.config import get_config
from pulse.storage.db import get_db
from pulse.scanner.engine import create_scanner
from pulse.scheduler.scheduler import get_scheduler
from pulse.services.oui_updater import get_oui_updater
from pulse.api.app import run_app


def setup_logging(config):
    """Setup logging configuration"""
    log_level = config.get('logging.level', 'INFO')
    log_format = config.get('logging.format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    log_file = config.get('logging.file', 'logs/pulse.log')
    max_bytes = config.get('logging.max_bytes', 10485760)  # 10MB
    backup_count = config.get('logging.backup_count', 5)

    # Create logs directory
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level))

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, log_level))
    console_formatter = logging.Formatter(log_format)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # File handler with rotation
    if log_file:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        file_handler.setLevel(getattr(logging, log_level))
        file_formatter = logging.Formatter(log_format)
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)


def check_requirements(config):
    """Check system requirements"""
    logger = logging.getLogger(__name__)

    # Check Nmap
    scanner = create_scanner(config)
    success, message = scanner.check_requirements()

    if not success:
        logger.error(f"Requirements check failed: {message}")
        logger.error("Please install Nmap: https://nmap.org/download.html")
        return False

    logger.info(f"Requirements check: {message}")
    return True


def initialize_system(config):
    """Initialize system components"""
    logger = logging.getLogger(__name__)

    logger.info("=" * 60)
    logger.info("Pulse Network Monitor - Starting")
    logger.info(f"Platform: {sys.platform}")
    logger.info("=" * 60)

    # Initialize database
    logger.info("Initializing database...")
    db = get_db(config.get('database.path'))
    logger.info("Database initialized")

    # Check OUI database
    logger.info("Checking OUI database...")
    oui_updater = get_oui_updater(config, db)

    if oui_updater.should_update():
        logger.info("OUI database needs update, downloading...")
        success, message = oui_updater.update()
        if success:
            logger.info(f"OUI database updated: {message}")
        else:
            logger.warning(f"OUI update failed: {message}")
    else:
        last_update = oui_updater.get_last_update()
        logger.info(f"OUI database is up to date (last update: {last_update})")

    logger.info("System initialization complete")


def run_server(args, config):
    """Run API server"""
    logger = logging.getLogger(__name__)

    # Override config with command line args
    if args.host:
        config.set('api.host', args.host)
    if args.port:
        config.set('api.port', args.port)
    if args.debug:
        config.set('api.debug', True)

    # Start server
    run_app(
        host=config.get('api.host'),
        port=int(config.get('api.port')),
        debug=config.get('api.debug')
    )


def run_scan(args, config):
    """Run a single scan"""
    logger = logging.getLogger(__name__)

    scanner = create_scanner(config)

    logger.info(f"Starting {args.type} scan of {args.target}")

    if args.type == 'discovery':
        result = scanner.discovery_scan(args.target)
    elif args.type == 'quick':
        result = scanner.quick_scan(args.target)
    elif args.type == 'deep':
        result = scanner.deep_scan(args.target)
    elif args.type == 'full':
        result = scanner.full_scan(args.target)
    else:
        logger.error(f"Unknown scan type: {args.type}")
        return

    if result.get('success'):
        logger.info(f"Scan completed in {result.get('duration', 0):.2f}s")

        # Parse and display results
        from pulse.parser.nmap_parser import create_parser
        parser = create_parser()

        if result.get('xml_output'):
            parsed = parser.parse_xml(result['xml_output'])
            devices = parser.extract_devices(parsed)

            logger.info(f"Found {len(devices)} device(s)")

            for device in devices:
                logger.info(f"  - {device.get('ip_address')} "
                           f"({device.get('hostname', 'unknown')}) "
                           f"[{device.get('vendor', 'unknown')}]")
    else:
        logger.error(f"Scan failed: {result.get('error', 'Unknown error')}")


def run_update_oui(args, config):
    """Update OUI database"""
    logger = logging.getLogger(__name__)

    db = get_db(config.get('database.path'))
    oui_updater = get_oui_updater(config, db)

    logger.info("Updating OUI database...")
    success, message = oui_updater.update()

    if success:
        logger.info(f"Update successful: {message}")
    else:
        logger.error(f"Update failed: {message}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Pulse Network Monitor - Network discovery and monitoring system',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '--config',
        help='Path to configuration file',
        default=None
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Server command
    server_parser = subparsers.add_parser('server', help='Run API server')
    server_parser.add_argument('--host', help='Server host')
    server_parser.add_argument('--port', type=int, help='Server port')
    server_parser.add_argument('--debug', action='store_true', help='Debug mode')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run a single scan')
    scan_parser.add_argument(
        'type',
        choices=['discovery', 'quick', 'deep', 'full'],
        help='Scan type'
    )
    scan_parser.add_argument('target', help='Target IP or network (e.g., 192.168.1.0/24)')

    # Update OUI command
    oui_parser = subparsers.add_parser('update-oui', help='Update OUI database')

    args = parser.parse_args()

    # Load configuration
    config = get_config()
    if args.config:
        config.load_config(args.config)

    # Setup logging
    setup_logging(config)
    logger = logging.getLogger(__name__)

    try:
        # Check requirements
        if not check_requirements(config):
            sys.exit(1)

        # Initialize system
        initialize_system(config)

        # Execute command
        if args.command == 'server' or args.command is None:
            run_server(args if args.command else argparse.Namespace(host=None, port=None, debug=False), config)
        elif args.command == 'scan':
            run_scan(args, config)
        elif args.command == 'update-oui':
            run_update_oui(args, config)
        else:
            parser.print_help()

    except KeyboardInterrupt:
        logger.info("\nShutdown requested by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
