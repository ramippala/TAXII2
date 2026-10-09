# TAXII Server Implementation Guide

## Overview

This guide explains how to implement and deploy a TAXII 2 server that feeds STIX 2.1 threat intelligence to Trend Micro Vision One / Apex Central via the Suspicious Object List API.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    TAXII Server Implementation                │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  Flask API   │    │  Taxii2-      │    │   Memory     │  │
│  │   /feed      │───▶│  Client       │───▶│    Store     │  │
│  └──────────────┘    │  Publisher    │    │   (STIX 2.1) │  │
│                      └──────────────┘    └──────────────┘  │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  Subscriptions│    │  Auth        │    │  Health Check│  │
│  │   /sub/      │    │   /auth      │    │   /health    │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              ▲
                              │
                    ┌────────────────┐
                    │  Trend Micro  │
                    │   Polling      │
                    │   Clients      │
                    └────────────────┘
```

## System Components

### 1. TAXII 2 Server (Flask Application)
- **Purpose**: Hosts TAXII 2 protocol endpoints
- **Technology**: Python Flask web framework
- **Protocol**: TAXII 2.0 over HTTP
- **Format**: STIX 2.1 JSON responses

### 2. Memory Backend (SQLite + SQLAlchemy)
- **Purpose**: Persistent storage for threat intelligence
- **Data Model**: 
  - STIX objects (indicators, IPs, domains, file hashes)
  - Subscription records
  - Authentication credentials

### 3. API Endpoints
- `/feed` - Returns latest STIX feed
- `/feed/ingest` - Accepts new threat data
- `/feed/purge` - Clear all data
- `/auth` - Client authentication
- `/subscriptions` - Manage subscriptions
- `/health` - Health check endpoint

## Installation Steps

### Prerequisites
- Python 3.8+ with pip
- Virtual environment (recommended)
- Git for version control

### Step 1: Clone Repository
```bash
cd /home/gojo/code/TAXII
pip install -r requirements.txt
```

### Step 2: Verify Installation
```bash
python server.py
# Should start on port 5000
```

## API Endpoints

### GET /feed
Returns latest STIX feed in TAXII 2 format.

**Request:**
```bash
curl http://localhost:5000/feed
```

**Response:**
```xml
<Response xmlns="stix-taxon" xmlns:v2_1="http://cyclonedx.org/schema/cyclonedx/1.3">
  <body>
    <!-- TAXII 2 formatted STIX bundle -->
  </body>
</Response>
```

### POST /feed/ingest
Accepts STIX 2.1 JSON for ingestion.

**Request Body:**
```json
{
  "stix_objects": [
    {
      "id": "indicator--abc123",
      "type": "indicator",
      "object": {
        "indicator": {
          "value": "Suspicious Activity",
          "label": "malware-indicator",
          "confidence": 80,
          "references": ["ipv4-addr--123", "file-hash--456"]
        }
      }
    },
    {
      "id": "ipv4-addr--123",
      "type": "ipv4-addr",
      "object": {
        "ipv4-addr": {"value": "192.168.1.100"}
      }
    },
    {
      "id": "domain-name--789",
      "type": "domain-name",
      "object": {
        "domain-name": {"value": "malicious-example.com"}
      }
    }
  ]
}
```

**Response:**
```json
{
  "message": "Data ingested successfully",
  "objects_count": 42
}
```

### DELETE /feed/purge
Purges all threat intelligence data from memory.

### GET /health
Health check endpoint for monitoring.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2023-10-07T10:30:00",
  "objects_count": 42
}
```

## Trend Micro Integration Guide

### Configuration Steps

#### 1. Create Suspicious Object List (SOL) in Trend Micro
- Navigate to Vision One Apex Central Admin Console
- Create a new SOL
- Define list name and description
- Configure object types (IP addresses, file hashes, domains)

#### 2. Configure Polling Settings
- Set polling interval (recommended: every 15-30 minutes)
- Configure authentication credentials
- Enable XML response parsing
- Set up error handling

#### 3. Authentication Setup
```bash
POST http://localhost:5000/auth
Content-Type: application/x-www-form-urlencoded
username=<your-username>
password=<your-password>
```

#### 4. Subscription Management
```bash
# Add subscription
curl -X POST http://localhost:5000/subscriptions/TrendMicroClient \
  -H "Content-Type: application/json" \
  -d '{"password": "secure_password"}'

# List subscriptions
curl http://localhost:5000/subscriptions
```

### Best Practices

1. **Security**
   - Use HTTPS for production deployments
   - Implement proper authentication
   - Rate limit API endpoints
   - Enable CORS only if needed

2. **Performance**
   - Cache feed responses when possible
   - Implement pagination for large feeds
   - Monitor database growth

3. **Monitoring**
   - Track feed retrieval success rate
   - Monitor error rates
   - Log suspicious access patterns

## Testing

### Unit Tests
```bash
python tests/test_server.py
```

### Integration Tests
1. Start server
2. Test ingestion:
   ```bash
   curl -X POST http://localhost:5000/feed/ingest \
     -H "Content-Type: application/json" \
     -d '{"stix_objects": [...]}'
   ```
3. Retrieve feed:
   ```bash
   curl http://localhost:5000/feed
   ```

## Deployment Considerations

### Production Requirements
- Use HTTPS/TLS
- Implement rate limiting
- Configure logging
- Set up monitoring and alerts
- Backup database regularly

### Environment Variables
```bash
export FLASK_SECRET=your-secret-key
export DATABASE_URL=sqlite:///taxii_feed.db
export FLASK_DEBUG=0
```

## Troubleshooting

### Common Issues

#### Connection Errors
1. Verify server is running: `curl http://localhost:5000/health`
2. Check firewall rules
3. Confirm network connectivity

#### Authentication Failures
1. Verify username/password format
2. Check /auth endpoint returns success
3. Ensure credentials match subscription requirements

#### Feed Retrieval Errors
1. Verify TAXII client configuration
2. Check response format compatibility
3. Validate STIX object structure

### Debug Mode
Enable debug mode for detailed logs:
```yaml
server:
  debug: true
```

## Maintenance

### Database Maintenance
- Regular backups
- Index optimization
- Cleanup old data

### Performance Optimization
- Monitor memory usage
- Tune cache settings
- Optimize database queries

## Security Checklist

- [ ] Strong passwords for authentication
- [ ] HTTPS enabled in production
- [ ] Rate limiting configured
- [ ] CORS properly configured
- [ ] Logging enabled (without secrets)
- [ ] Error handling implemented
- [ ] Security audits scheduled

## License

MIT License
