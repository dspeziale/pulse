"""
Alert service for sending notifications via multiple channels
Supports webhook, email, and Telegram
"""

import logging
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List, Optional

from pulse.utils.config import get_config
from pulse.storage.db import get_db

logger = logging.getLogger(__name__)


class AlertService:
    """Alert notification service"""

    def __init__(self, config=None, db=None):
        """Initialize alert service"""
        self.config = config or get_config()
        self.db = db or get_db()

        self.enabled = self.config.get('alerts.enabled', True)

    def send_alert(
        self,
        title: str,
        message: str,
        severity: str = 'info',
        device_id: int = None,
        metadata: Dict = None
    ):
        """
        Send alert through configured channels

        Args:
            title: Alert title
            message: Alert message
            severity: Alert severity (info, warning, critical)
            device_id: Related device ID
            metadata: Additional metadata
        """
        if not self.enabled:
            logger.debug("Alerts disabled, skipping")
            return

        # Create event in database
        self.db.create_event({
            'event_type': 'alert',
            'severity': severity,
            'device_id': device_id,
            'title': title,
            'description': message,
            'metadata': metadata or {}
        })

        # Send through enabled channels
        channels = self.config.get('alerts.channels', {})

        if channels.get('webhook', {}).get('enabled'):
            self._send_webhook(title, message, severity, metadata)

        if channels.get('email', {}).get('enabled'):
            self._send_email(title, message, severity)

        if channels.get('telegram', {}).get('enabled'):
            self._send_telegram(title, message, severity)

    def _send_webhook(self, title: str, message: str, severity: str, metadata: Dict = None):
        """Send alert via webhook"""
        try:
            webhook_url = self.config.get('alerts.channels.webhook.url')

            if not webhook_url:
                logger.warning("Webhook enabled but URL not configured")
                return

            payload = {
                'title': title,
                'message': message,
                'severity': severity,
                'timestamp': self.db.get_connection().execute('SELECT CURRENT_TIMESTAMP').fetchone()[0],
                'metadata': metadata or {}
            }

            response = requests.post(
                webhook_url,
                json=payload,
                timeout=10
            )

            response.raise_for_status()
            logger.info(f"Webhook alert sent: {title}")

        except Exception as e:
            logger.error(f"Error sending webhook alert: {e}")

    def _send_email(self, title: str, message: str, severity: str):
        """Send alert via email"""
        try:
            smtp_server = self.config.get('alerts.channels.email.smtp_server')
            smtp_port = self.config.get('alerts.channels.email.smtp_port', 587)
            username = self.config.get('alerts.channels.email.smtp_username')
            password = self.config.get('alerts.channels.email.smtp_password')
            from_address = self.config.get('alerts.channels.email.from_address')
            to_addresses = self.config.get('alerts.channels.email.to_addresses', [])

            if not all([smtp_server, username, password, from_address, to_addresses]):
                logger.warning("Email enabled but not fully configured")
                return

            # Create message
            msg = MIMEMultipart()
            msg['From'] = from_address
            msg['To'] = ', '.join(to_addresses)
            msg['Subject'] = f"[{severity.upper()}] {title}"

            body = f"""
Pulse Network Monitor Alert

Severity: {severity.upper()}
Title: {title}

Message:
{message}

---
This is an automated alert from Pulse Network Monitor
"""

            msg.attach(MIMEText(body, 'plain'))

            # Send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(username, password)
                server.send_message(msg)

            logger.info(f"Email alert sent: {title}")

        except Exception as e:
            logger.error(f"Error sending email alert: {e}")

    def _send_telegram(self, title: str, message: str, severity: str):
        """Send alert via Telegram bot"""
        try:
            bot_token = self.config.get('alerts.channels.telegram.bot_token')
            chat_id = self.config.get('alerts.channels.telegram.chat_id')

            if not all([bot_token, chat_id]):
                logger.warning("Telegram enabled but not fully configured")
                return

            # Format message
            severity_emoji = {
                'info': 'ℹ️',
                'warning': '⚠️',
                'critical': '🚨'
            }

            text = f"{severity_emoji.get(severity, '🔔')} *{severity.upper()}*\n\n"
            text += f"*{title}*\n\n"
            text += message

            # Send message
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {
                'chat_id': chat_id,
                'text': text,
                'parse_mode': 'Markdown'
            }

            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()

            logger.info(f"Telegram alert sent: {title}")

        except Exception as e:
            logger.error(f"Error sending Telegram alert: {e}")

    def alert_new_device(self, device_data: Dict[str, Any]):
        """Send alert for new device discovered"""
        if not self.config.get('alerts.rules.new_device.enabled', True):
            return

        ip_address = device_data.get('ip_address')
        hostname = device_data.get('hostname', 'Unknown')
        vendor = device_data.get('vendor', 'Unknown')

        self.send_alert(
            title=f"New Device Discovered: {ip_address}",
            message=f"A new device has been discovered on the network.\n\n"
                    f"IP Address: {ip_address}\n"
                    f"Hostname: {hostname}\n"
                    f"Vendor: {vendor}\n"
                    f"Type: {device_data.get('device_type', 'unknown')}",
            severity='info',
            device_id=device_data.get('id'),
            metadata=device_data
        )

    def alert_device_offline(self, device_data: Dict[str, Any]):
        """Send alert for device going offline"""
        if not self.config.get('alerts.rules.device_offline.enabled', True):
            return

        ip_address = device_data.get('ip_address')
        hostname = device_data.get('hostname', 'Unknown')

        self.send_alert(
            title=f"Device Offline: {ip_address}",
            message=f"A device has gone offline.\n\n"
                    f"IP Address: {ip_address}\n"
                    f"Hostname: {hostname}\n"
                    f"Last seen: {device_data.get('last_seen')}",
            severity='warning',
            device_id=device_data.get('id'),
            metadata=device_data
        )

    def alert_suspicious_device(self, device_data: Dict[str, Any], reasons: List[str]):
        """Send alert for suspicious device"""
        if not self.config.get('alerts.rules.suspicious_port.enabled', True):
            return

        ip_address = device_data.get('ip_address')
        hostname = device_data.get('hostname', 'Unknown')

        reasons_text = '\n'.join(f"- {reason}" for reason in reasons)

        self.send_alert(
            title=f"Suspicious Device Detected: {ip_address}",
            message=f"A potentially suspicious device has been detected.\n\n"
                    f"IP Address: {ip_address}\n"
                    f"Hostname: {hostname}\n\n"
                    f"Reasons:\n{reasons_text}",
            severity='critical',
            device_id=device_data.get('id'),
            metadata={'reasons': reasons, **device_data}
        )

    def alert_new_port(self, device_data: Dict[str, Any], port_data: Dict[str, Any]):
        """Send alert for new open port"""
        if not self.config.get('alerts.rules.new_port.enabled', True):
            return

        ip_address = device_data.get('ip_address')
        port_number = port_data.get('port_number')
        service_name = port_data.get('service_name', 'unknown')

        self.send_alert(
            title=f"New Port Detected: {ip_address}:{port_number}",
            message=f"A new open port has been detected.\n\n"
                    f"Device: {ip_address}\n"
                    f"Port: {port_number}/{port_data.get('protocol', 'tcp')}\n"
                    f"Service: {service_name}\n"
                    f"State: {port_data.get('state')}",
            severity='info',
            device_id=device_data.get('id'),
            metadata=port_data
        )


# Global instance
_alert_service = None


def get_alert_service(config=None, db=None) -> AlertService:
    """Get alert service singleton instance"""
    global _alert_service
    if _alert_service is None:
        _alert_service = AlertService(config, db)
    return _alert_service
