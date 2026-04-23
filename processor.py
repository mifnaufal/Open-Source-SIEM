#!/usr/bin/env python3
"""
SIEM Processor - Layer 2: Processing Engine
Handles log parsing, enrichment, correlation, and alerting
"""

import os
import re
import json
import time
import logging
import yaml
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from collections import defaultdict

import redis
from elasticsearch import Elasticsearch
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('siem-processor')


@dataclass
class NormalizedEvent:
    """Standardized event format"""
    timestamp: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    event_type: str
    severity: str
    message: str
    raw_log: str
    source_host: str
    geo_info: Optional[Dict] = None
    threat_intel: Optional[Dict] = None
    rule_id: Optional[str] = None


class LogParser:
    """Parse various log formats into normalized events"""
    
    # Common log patterns
    PATTERNS = {
        'syslog': re.compile(
            r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
            r'(?P<message>.*)$'
        ),
        'sshd_failed_login': re.compile(
            r'Failed password for (?:invalid user )?(?P<user>\S+) from '
            r'(?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)'
        ),
        'sshd_accepted_login': re.compile(
            r'Accepted \S+ for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) '
            r'port (?P<port>\d+)'
        ),
        'apache_access': re.compile(
            r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+'
            r'"(?P<method>\w+)\s+(?P<path>\S+)\s+[^"]+"\s+(?P<status>\d+)\s+(?P<size>\d+)'
        ),
        'cef': re.compile(  # Common Event Format
            r'^CEF:(?P<version>\d+)\|(?P<vendor>\S*)\|(?P<product>\S*)\|'
            r'(?P<prod_version>\S*)\|(?P<signature>\S*)\|(?P<name>[^|]*)\|'
            r'(?P<severity>\d)\|(?P<extension>.*)$'
        )
    }
    
    def parse(self, raw_log: str, source_host: str = 'unknown') -> Optional[NormalizedEvent]:
        """Parse raw log into normalized event"""
        try:
            # Try syslog format first
            match = self.PATTERNS['syslog'].match(raw_log)
            if match:
                return self._parse_syslog(match, raw_log, source_host)
            
            # Try CEF format
            match = self.PATTERNS['cef'].match(raw_log)
            if match:
                return self._parse_cef(match, raw_log, source_host)
            
            # Try Apache access log
            match = self.PATTERNS['apache_access'].match(raw_log)
            if match:
                return self._parse_apache(match, raw_log, source_host)
            
            # Generic JSON log
            if raw_log.startswith('{'):
                try:
                    data = json.loads(raw_log)
                    return self._parse_json(data, raw_log, source_host)
                except json.JSONDecodeError:
                    pass
            
            # Fallback: create basic event
            return self._create_generic_event(raw_log, source_host)
            
        except Exception as e:
            logger.error(f"Error parsing log: {e}")
            return None
    
    def _parse_syslog(self, match, raw_log: str, source_host: str) -> NormalizedEvent:
        """Parse syslog format"""
        msg = match.group('message')
        
        # Check for SSH failed login
        ssh_match = self.PATTERNS['sshd_failed_login'].search(msg)
        if ssh_match:
            return NormalizedEvent(
                timestamp=datetime.now().isoformat(),
                source_ip=ssh_match.group('ip'),
                destination_ip='0.0.0.0',
                source_port=int(ssh_match.group('port')),
                destination_port=22,
                protocol='TCP',
                event_type='authentication_failure',
                severity='medium',
                message=f"Failed SSH login attempt for user {ssh_match.group('user')}",
                raw_log=raw_log,
                source_host=source_host or match.group('host')
            )
        
        # Check for SSH accepted login
        ssh_match = self.PATTERNS['sshd_accepted_login'].search(msg)
        if ssh_match:
            return NormalizedEvent(
                timestamp=datetime.now().isoformat(),
                source_ip=ssh_match.group('ip'),
                destination_ip='0.0.0.0',
                source_port=int(ssh_match.group('port')),
                destination_port=22,
                protocol='TCP',
                event_type='authentication_success',
                severity='info',
                message=f"Successful SSH login for user {ssh_match.group('user')}",
                raw_log=raw_log,
                source_host=source_host or match.group('host')
            )
        
        # Generic syslog
        return NormalizedEvent(
            timestamp=datetime.now().isoformat(),
            source_ip='0.0.0.0',
            destination_ip='0.0.0.0',
            source_port=0,
            destination_port=0,
            protocol='UNKNOWN',
            event_type='syslog',
            severity='info',
            message=msg,
            raw_log=raw_log,
            source_host=source_host or match.group('host')
        )
    
    def _parse_cef(self, match, raw_log: str, source_host: str) -> NormalizedEvent:
        """Parse CEF format"""
        return NormalizedEvent(
            timestamp=datetime.now().isoformat(),
            source_ip='0.0.0.0',
            destination_ip='0.0.0.0',
            source_port=0,
            destination_port=0,
            protocol='UNKNOWN',
            event_type=match.group('signature'),
            severity=self._cef_severity_to_level(int(match.group('severity'))),
            message=match.group('name'),
            raw_log=raw_log,
            source_host=source_host
        )
    
    def _parse_apache(self, match, raw_log: str, source_host: str) -> NormalizedEvent:
        """Parse Apache access log"""
        status = int(match.group('status'))
        severity = 'info'
        event_type = 'http_access'
        
        if status >= 500:
            severity = 'high'
            event_type = 'http_server_error'
        elif status >= 400:
            severity = 'medium'
            event_type = 'http_client_error'
        
        return NormalizedEvent(
            timestamp=datetime.now().isoformat(),
            source_ip=match.group('ip'),
            destination_ip='0.0.0.0',
            source_port=0,
            destination_port=80,
            protocol='HTTP',
            event_type=event_type,
            severity=severity,
            message=f"{match.group('method')} {match.group('path')} - {status}",
            raw_log=raw_log,
            source_host=source_host
        )
    
    def _parse_json(self, data: Dict, raw_log: str, source_host: str) -> NormalizedEvent:
        """Parse JSON formatted log"""
        return NormalizedEvent(
            timestamp=data.get('timestamp', datetime.now().isoformat()),
            source_ip=data.get('source_ip', '0.0.0.0'),
            destination_ip=data.get('destination_ip', '0.0.0.0'),
            source_port=data.get('source_port', 0),
            destination_port=data.get('destination_port', 0),
            protocol=data.get('protocol', 'UNKNOWN'),
            event_type=data.get('event_type', 'generic'),
            severity=data.get('severity', 'info'),
            message=data.get('message', ''),
            raw_log=raw_log,
            source_host=data.get('source_host', source_host)
        )
    
    def _create_generic_event(self, raw_log: str, source_host: str) -> NormalizedEvent:
        """Create generic event for unmatched logs"""
        return NormalizedEvent(
            timestamp=datetime.now().isoformat(),
            source_ip='0.0.0.0',
            destination_ip='0.0.0.0',
            source_port=0,
            destination_port=0,
            protocol='UNKNOWN',
            event_type='generic',
            severity='info',
            message=raw_log[:200],  # Truncate long messages
            raw_log=raw_log,
            source_host=source_host
        )
    
    def _cef_severity_to_level(self, severity: int) -> str:
        """Convert CEF severity to level string"""
        if severity >= 9:
            return 'critical'
        elif severity >= 7:
            return 'high'
        elif severity >= 4:
            return 'medium'
        elif severity >= 1:
            return 'low'
        return 'info'


class ThreatIntelligence:
    """Enrich events with threat intelligence"""
    
    def __init__(self):
        self.abuseipdb_key = os.getenv('ABUSEIPDB_KEY', '')
        self.maxmind_license = os.getenv('MAXMIND_LICENSE', '')
    
    def enrich(self, event: NormalizedEvent) -> NormalizedEvent:
        """Enrich event with threat intel and geo info"""
        if event.source_ip and event.source_ip != '0.0.0.0':
            # GeoIP enrichment (simplified - would use MaxMind in production)
            event.geo_info = self._get_geo_info(event.source_ip)
            
            # AbuseIPDB check (if API key available)
            if self.abuseipdb_key:
                event.threat_intel = self._check_abuseipdb(event.source_ip)
        
        return event
    
    def _get_geo_info(self, ip: str) -> Dict:
        """Get geographic information for IP (mock implementation)"""
        # In production, use MaxMind GeoIP2 database
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'latitude': 0.0,
            'longitude': 0.0
        }
    
    def _check_abuseipdb(self, ip: str) -> Optional[Dict]:
        """Check IP against AbuseIPDB"""
        try:
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers={'Key': self.abuseipdb_key},
                params={'ipAddress': ip, 'maxAgeInDays': 90},
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    'abuse_score': data['data'].get('abuseConfidenceScore', 0),
                    'total_reports': data['data'].get('totalReports', 0),
                    'is_malicious': data['data'].get('abuseConfidenceScore', 0) > 50
                }
        except Exception as e:
            logger.error(f"AbuseIPDB check failed: {e}")
        return None


class CorrelationEngine:
    """Rule-based correlation engine"""
    
    def __init__(self, rules_dir: str = 'rules'):
        self.rules_dir = rules_dir
        self.rules = []
        self.event_buffer = defaultdict(list)  # Buffer for time-window correlation
        self.load_rules()
    
    def load_rules(self):
        """Load correlation rules from YAML files"""
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir)
            self._create_default_rules()
        
        for filename in sorted(os.listdir(self.rules_dir)):
            if filename.endswith('.yaml') or filename.endswith('.yml'):
                filepath = os.path.join(self.rules_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        content = f.read()
                        # Handle multiple documents in single file
                        for rule_data in yaml.safe_load_all(content):
                            if rule_data:
                                self.rules.append(rule_data)
                                logger.info(f"Loaded rule: {rule_data.get('name', 'Unknown')}")
                except Exception as e:
                    logger.error(f"Error loading rule {filename}: {e}")
    
    def _create_default_rules(self):
        """Create default correlation rules"""
        # Rule 1: Multiple failed SSH logins
        ssh_bruteforce_rule = {
            'id': 'SSH-BRUTEFORCE-001',
            'name': 'SSH Brute Force Detection',
            'description': 'Detect multiple failed SSH login attempts',
            'enabled': True,
            'conditions': {
                'event_type': 'authentication_failure',
                'destination_port': 22
            },
            'threshold': 5,
            'time_window': 60,  # seconds
            'group_by': 'source_ip',
            'severity': 'high',
            'alert_message': 'Possible SSH brute force attack from {source_ip}'
        }
        
        # Rule 2: Port scanning detection
        port_scan_rule = {
            'id': 'PORT-SCAN-001',
            'name': 'Port Scan Detection',
            'description': 'Detect potential port scanning activity',
            'enabled': True,
            'conditions': {
                'protocol': 'TCP'
            },
            'threshold': 10,
            'time_window': 60,
            'group_by': 'source_ip',
            'unique_field': 'destination_port',
            'severity': 'medium',
            'alert_message': 'Possible port scan from {source_ip}'
        }
        
        # Save rules
        with open(os.path.join(self.rules_dir, 'ssh_bruteforce.yaml'), 'w') as f:
            yaml.dump(ssh_bruteforce_rule, f)
        
        with open(os.path.join(self.rules_dir, 'port_scan.yaml'), 'w') as f:
            yaml.dump(port_scan_rule, f)
    
    def evaluate(self, event: NormalizedEvent) -> List[Dict]:
        """Evaluate event against all rules"""
        alerts = []
        
        for rule in self.rules:
            if not rule.get('enabled', True):
                continue
            
            if self._matches_conditions(event, rule['conditions']):
                alert = self._check_threshold(event, rule)
                if alert:
                    alerts.append(alert)
        
        return alerts
    
    def _matches_conditions(self, event: NormalizedEvent, conditions: Dict) -> bool:
        """Check if event matches rule conditions"""
        for key, value in conditions.items():
            event_value = getattr(event, key, None)
            if event_value != value:
                return False
        return True
    
    def _check_threshold(self, event: NormalizedEvent, rule: Dict) -> Optional[Dict]:
        """Check if event threshold is exceeded"""
        group_key = getattr(event, rule.get('group_by', 'source_ip'), 'unknown')
        current_time = time.time()
        time_window = rule.get('time_window', 60)
        threshold = rule.get('threshold', 1)
        
        # Add event to buffer
        buffer_key = f"{rule['id']}:{group_key}"
        self.event_buffer[buffer_key].append({
            'timestamp': current_time,
            'event': event,
            'unique_value': getattr(event, rule.get('unique_field', 'destination_port'), None)
        })
        
        # Clean old events
        cutoff = current_time - time_window
        self.event_buffer[buffer_key] = [
            e for e in self.event_buffer[buffer_key] if e['timestamp'] > cutoff
        ]
        
        # Check threshold
        events_in_window = self.event_buffer[buffer_key]
        
        if rule.get('unique_field'):
            # Count unique values (for port scan detection)
            unique_values = set(e['unique_value'] for e in events_in_window)
            count = len(unique_values)
        else:
            count = len(events_in_window)
        
        if count >= threshold:
            # Clear buffer after alert
            self.event_buffer[buffer_key] = []
            
            # Build alert with event_count available for formatting
            alert_dict = {
                'rule_id': rule['id'],
                'rule_name': rule['name'],
                'severity': rule.get('severity', 'medium'),
                'source_ip': event.source_ip,
                'timestamp': datetime.now().isoformat(),
                'event_count': count,
                'raw_events': [e['event'].raw_log for e in events_in_window[-5:]]  # Last 5 events
            }
            
            # Add all event fields for message formatting
            format_context = asdict(event)
            format_context['event_count'] = count
            
            alert_dict['message'] = rule.get('alert_message', '').format(**format_context)
            
            return alert_dict
        
        return None


class AlertManager:
    """Manage and send alerts"""
    
    def __init__(self):
        self.telegram_bot_token = os.getenv('TELEGRAM_BOT_TOKEN', '')
        self.telegram_chat_id = os.getenv('TELEGRAM_CHAT_ID', '')
        self.webhook_url = os.getenv('ALERT_WEBHOOK_URL', '')
    
    def send_alert(self, alert: Dict):
        """Send alert to configured channels"""
        logger.warning(f"ALERT: {alert['rule_name']} - {alert['message']}")
        
        # Send to Telegram
        if self.telegram_bot_token and self.telegram_chat_id:
            self._send_telegram(alert)
        
        # Send to webhook
        if self.webhook_url:
            self._send_webhook(alert)
        
        # Also store alert in Elasticsearch
        # (handled by SIEMProcessor)
    
    def _send_telegram(self, alert: Dict):
        """Send alert to Telegram"""
        try:
            message = (
                f"🚨 *SIEM Alert*\n\n"
                f"*Rule:* {alert['rule_name']}\n"
                f"*Severity:* {alert['severity'].upper()}\n"
                f"*Message:* {alert['message']}\n"
                f"*Source IP:* {alert['source_ip']}\n"
                f"*Event Count:* {alert['event_count']}\n"
                f"*Time:* {alert['timestamp']}"
            )
            
            url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
            requests.post(url, json={
                'chat_id': self.telegram_chat_id,
                'text': message,
                'parse_mode': 'Markdown'
            }, timeout=10)
            
            logger.info("Telegram alert sent")
        except Exception as e:
            logger.error(f"Failed to send Telegram alert: {e}")
    
    def _send_webhook(self, alert: Dict):
        """Send alert to webhook"""
        try:
            requests.post(self.webhook_url, json=alert, timeout=10)
            logger.info("Webhook alert sent")
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")


class SIEMProcessor:
    """Main SIEM processing pipeline"""
    
    def __init__(self):
        # Configuration
        self.redis_host = os.getenv('REDIS_HOST', 'localhost')
        self.redis_port = int(os.getenv('REDIS_PORT', 6379))
        self.es_host = os.getenv('ELASTICSEARCH_HOST', 'localhost')
        self.es_port = int(os.getenv('ELASTICSEARCH_PORT', 9200))
        
        # Initialize components
        self.parser = LogParser()
        self.enricher = ThreatIntelligence()
        self.correlation = CorrelationEngine()
        self.alert_manager = AlertManager()
        
        # Initialize connections
        self.redis_client = None
        self.es_client = None
        
        self._connect_redis()
        self._connect_elasticsearch()
    
    def _connect_redis(self):
        """Connect to Redis"""
        try:
            self.redis_client = redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                decode_responses=True
            )
            self.redis_client.ping()
            logger.info(f"Connected to Redis at {self.redis_host}:{self.redis_port}")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self.redis_client = None
    
    def _connect_elasticsearch(self):
        """Connect to Elasticsearch"""
        try:
            self.es_client = Elasticsearch(
                hosts=[f"http://{self.es_host}:{self.es_port}"],
                request_timeout=30
            )
            # Test connection
            info = self.es_client.info()
            logger.info(f"Connected to Elasticsearch: {info['version']['number']}")
            
            # Create index template
            self._setup_indices()
        except Exception as e:
            logger.error(f"Failed to connect to Elasticsearch: {e}")
            self.es_client = None
    
    def _setup_indices(self):
        """Setup Elasticsearch indices"""
        # Events index
        events_index = "siem-events"
        if not self.es_client.indices.exists(index=events_index):
            self.es_client.indices.create(
                index=events_index,
                mappings={
                    "properties": {
                        "timestamp": {"type": "date"},
                        "source_ip": {"type": "ip"},
                        "destination_ip": {"type": "ip"},
                        "source_port": {"type": "integer"},
                        "destination_port": {"type": "integer"},
                        "protocol": {"type": "keyword"},
                        "event_type": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "message": {"type": "text"},
                        "source_host": {"type": "keyword"},
                        "geo_info": {"type": "object"},
                        "threat_intel": {"type": "object"}
                    }
                }
            )
            logger.info(f"Created index: {events_index}")
        
        # Alerts index
        alerts_index = "siem-alerts"
        if not self.es_client.indices.exists(index=alerts_index):
            self.es_client.indices.create(
                index=alerts_index,
                mappings={
                    "properties": {
                        "timestamp": {"type": "date"},
                        "rule_id": {"type": "keyword"},
                        "rule_name": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "source_ip": {"type": "ip"},
                        "event_count": {"type": "integer"}
                    }
                }
            )
            logger.info(f"Created index: {alerts_index}")
    
    def process_stream(self):
        """Process logs from Redis Streams"""
        if not self.redis_client:
            logger.error("Redis not connected, cannot process stream")
            return
        
        stream_name = "siem:logs"
        last_id = "0"
        
        logger.info(f"Starting to process stream: {stream_name}")
        
        while True:
            try:
                # Read from stream
                messages = self.redis_client.xread(
                    streams={stream_name: last_id},
                    count=100,
                    block=5000  # Block for 5 seconds
                )
                
                if messages:
                    for stream, entries in messages:
                        for entry_id, fields in entries:
                            last_id = entry_id
                            
                            # Process each log entry
                            raw_log = fields.get('message', '')
                            source_host = fields.get('source_host', 'unknown')
                            
                            self.process_log(raw_log, source_host)
                
            except KeyboardInterrupt:
                logger.info("Shutting down...")
                break
            except Exception as e:
                logger.error(f"Error processing stream: {e}")
                time.sleep(5)
                
                # Reconnect if needed
                self._connect_redis()
                self._connect_elasticsearch()
    
    def process_log(self, raw_log: str, source_host: str = 'unknown'):
        """Process a single log entry"""
        if not raw_log.strip():
            return
        
        # Step 1: Parse
        event = self.parser.parse(raw_log, source_host)
        if not event:
            logger.debug(f"Failed to parse log: {raw_log[:100]}")
            return
        
        # Step 2: Enrich
        event = self.enricher.enrich(event)
        
        # Step 3: Store in Elasticsearch
        self._store_event(event)
        
        # Step 4: Correlation
        alerts = self.correlation.evaluate(event)
        
        # Step 5: Send alerts
        for alert in alerts:
            self.alert_manager.send_alert(alert)
            self._store_alert(alert)
    
    def _store_event(self, event: NormalizedEvent):
        """Store event in Elasticsearch"""
        if not self.es_client:
            return
        
        try:
            self.es_client.index(
                index="siem-events",
                document=asdict(event)
            )
        except Exception as e:
            logger.error(f"Failed to store event: {e}")
    
    def _store_alert(self, alert: Dict):
        """Store alert in Elasticsearch"""
        if not self.es_client:
            return
        
        try:
            self.es_client.index(
                index="siem-alerts",
                document=alert
            )
        except Exception as e:
            logger.error(f"Failed to store alert: {e}")
    
    def ingest_sample_logs(self, logs_file: str = 'sample_logs.txt'):
        """Ingest sample logs for testing (Phase 1)"""
        if not os.path.exists(logs_file):
            logger.warning(f"Sample logs file not found: {logs_file}")
            return
        
        logger.info(f"Ingesting sample logs from {logs_file}")
        
        with open(logs_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    self.process_log(line)
        
        logger.info("Sample log ingestion complete")


def main():
    """Main entry point"""
    processor = SIEMProcessor()
    
    # Check if we should ingest sample logs
    if os.getenv('INGEST_SAMPLE_LOGS', 'false').lower() == 'true':
        processor.ingest_sample_logs()
    
    # Start stream processing
    processor.process_stream()


if __name__ == '__main__':
    main()
