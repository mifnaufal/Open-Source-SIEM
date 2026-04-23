# SIEM Project - Security Information and Event Management

Complete open-source SIEM implementation with 4-layer architecture as described.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Layer 4: Presentation                     │
│                    Grafana | Kibana | Telegram/Slack             │
└─────────────────────────────────────────────────────────────────┘
                              ↑
┌─────────────────────────────────────────────────────────────────┐
│                         Layer 3: Storage                          │
│              Elasticsearch | OpenSearch | MinIO                  │
└─────────────────────────────────────────────────────────────────┘
                              ↑
┌─────────────────────────────────────────────────────────────────┐
│                        Layer 2: Processing                        │
│     Parser | Enrichment | Correlation Engine | Alert Manager     │
└─────────────────────────────────────────────────────────────────┘
                              ↑
┌─────────────────────────────────────────────────────────────────┐
│                         Layer 1: Ingestion                        │
│           Filebeat | Fluent Bit | Redis Streams | Kafka          │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.11+ (for local development)

### Phase 1: Basic Setup (Week 1-2)

1. **Start all services:**
```bash
docker-compose up -d
```

2. **Wait for services to be ready** (about 2-3 minutes for Elasticsearch)

3. **Test with sample logs:**
```bash
# Option A: Run processor directly with sample logs
docker-compose exec siem-processor python processor.py

# Option B: Use the ingest script (in another terminal)
python scripts/ingest_logs.py sample_logs.txt
```

4. **Access dashboards:**
- **Kibana**: http://localhost:5601
- **Grafana**: http://localhost:3000 (admin/admin123)
- **Elasticsearch**: http://localhost:9200

### Phase 2: Add Custom Rules (Week 3-4)

Edit correlation rules in `/rules/` directory:

```yaml
# Example: Custom rule
id: CUSTOM-001
name: My Custom Rule
description: Description of what this detects
enabled: true

conditions:
  event_type: authentication_failure
  destination_port: 22

threshold: 5
time_window: 60
group_by: source_ip

severity: high
alert_message: "Alert message with {source_ip} variable"
```

### Phase 3: Production Configuration (Month 2)

1. **Configure threat intelligence:**
```bash
export ABUSEIPDB_KEY=your_api_key
export MAXMIND_LICENSE=your_license_key
```

2. **Configure alerting:**
```bash
export TELEGRAM_BOT_TOKEN=your_bot_token
export TELEGRAM_CHAT_ID=your_chat_id
export ALERT_WEBHOOK_URL=https://your-webhook.com/alerts
```

3. **Deploy Filebeat/Fluent Bit** on your servers to send logs to Redis

## Components

### Layer 1: Ingestion
- **Redis Streams**: Message broker for log events
- **Filebeat/Fluent Bit**: Log collectors (configure separately)
- **Winlogbeat**: Windows log collection

### Layer 2: Processing (`processor.py`)
- **LogParser**: Supports Syslog, CEF, Apache, JSON formats
- **ThreatIntelligence**: GeoIP and AbuseIPDB enrichment
- **CorrelationEngine**: Rule-based detection with time windows
- **AlertManager**: Telegram, webhook, and Slack notifications

### Layer 3: Storage
- **Elasticsearch**: Event and alert storage
- **Kibana**: Built-in dashboards
- **Grafana**: Additional visualization

### Layer 4: Presentation
- **Grafana Dashboards**: Connect to Elasticsearch datasource
- **Kibana**: Native ES dashboards
- **Telegram/Slack**: Real-time alerts

## Directory Structure

```
/workspace
├── docker-compose.yml      # All services orchestration
├── Dockerfile              # SIEM processor container
├── requirements.txt        # Python dependencies
├── processor.py            # Main processing engine
├── sample_logs.txt         # Test log data
├── configs/
│   └── grafana/
│       └── datasources/    # Grafana datasource config
├── rules/
│   ├── ssh_bruteforce.yaml # SSH brute force detection
│   ├── port_scan.yaml      # Port scan detection
│   └── web_attacks.yaml    # Web attack detection
├── parsers/                # Custom parsers (extensible)
└── scripts/
    └── ingest_logs.py      # Log ingestion helper
```

## API Endpoints

### Elasticsearch
- `GET http://localhost:9200/siem-events/_search` - Search events
- `GET http://localhost:9200/siem-alerts/_search` - Search alerts

### Kibana
- `http://localhost:5601` - Create visualizations and dashboards

### Grafana
- `http://localhost:3000` - Pre-configured Elasticsearch datasource

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| REDIS_HOST | Redis hostname | localhost |
| REDIS_PORT | Redis port | 6379 |
| ELASTICSEARCH_HOST | ES hostname | localhost |
| ELASTICSEARCH_PORT | ES port | 9200 |
| ABUSEIPDB_KEY | AbuseIPDB API key | - |
| MAXMIND_LICENSE | MaxMind license | - |
| TELEGRAM_BOT_TOKEN | Telegram bot token | - |
| TELEGRAM_CHAT_ID | Telegram chat ID | - |
| ALERT_WEBHOOK_URL | Webhook URL for alerts | - |
| INGEST_SAMPLE_LOGS | Ingest sample logs on start | false |

## Development

### Run locally (without Docker):
```bash
# Start Redis and Elasticsearch manually
pip install -r requirements.txt

# Set environment variables
export REDIS_HOST=localhost
export ELASTICSEARCH_HOST=localhost

# Run processor
python processor.py
```

### Add new log format parser:
1. Add regex pattern to `LogParser.PATTERNS`
2. Implement `_parse_<format>()` method
3. Update `parse()` method to detect new format

### Add new correlation rule:
1. Create YAML file in `/rules/`
2. Define conditions, threshold, and time_window
3. Processor auto-loads new rules on restart

## Roadmap

- [x] Phase 1: Basic log collection and storage
- [x] Phase 2: Parser and basic correlation rules
- [ ] Phase 3: Threat intel enrichment, advanced correlation
- [ ] Phase 4: ML anomaly detection, SOAR integration

## License

MIT License - Feel free to use and modify!
