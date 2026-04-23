# SIEM Log Ingestor Script
# Sends logs to Redis Streams for processing

import redis
import time
import os

REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
STREAM_NAME = "siem:logs"

def ingest_logs(logs_file: str, source_host: str = 'test-server'):
    """Read logs from file and send to Redis Stream"""
    
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    
    try:
        # Test connection
        r.ping()
        print(f"Connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
    except redis.ConnectionError as e:
        print(f"Failed to connect to Redis: {e}")
        return
    
    print(f"Reading logs from {logs_file}...")
    
    with open(logs_file, 'r') as f:
        for line in f:
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Send to Redis Stream
            try:
                r.xadd(STREAM_NAME, {
                    'message': line,
                    'source_host': source_host,
                    'ingested_at': time.time()
                })
                print(f"Ingested: {line[:80]}...")
            except Exception as e:
                print(f"Error ingesting log: {e}")
            
            # Small delay to simulate real-time ingestion
            time.sleep(0.1)
    
    print(f"\nLog ingestion complete! Check the SIEM processor for processed events.")
    print(f"View events in Kibana at http://localhost:5601")
    print(f"View alerts in Elasticsearch index: siem-alerts")


if __name__ == '__main__':
    import sys
    
    logs_file = sys.argv[1] if len(sys.argv) > 1 else 'sample_logs.txt'
    source_host = sys.argv[2] if len(sys.argv) > 2 else 'test-server'
    
    ingest_logs(logs_file, source_host)
