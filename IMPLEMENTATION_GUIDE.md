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

### 2. Storage (SQLite / PostgreSQL / MariaDB via SQLAlchemy)
- **Purpose**: Persistent storage for threat intelligence, puller state and subscriptions
- **Data Model**: `stix_objects` (the feed), `puller_state` (poller delta + status), `subscriptions`
- **See**: [Database Schema & Production Setup](#database-schema--production-setup) for the full schema, DDL and production setup.

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

## Database Schema & Production Setup

The server keeps everything in **three tables**. The schema is defined by the
SQLAlchemy models in `server.py` (`STIXObject`, `PullerState`, `Subscription`)
and created automatically on first start (`Base.metadata.create_all()` inside
`init_db()`), so **no manual DDL is required** — but the exact DDL is below for
a DBA-managed deployment.

### Tables

| Table | Purpose |
|-------|---------|
| `stix_objects` | The feed — one row per STIX id. IOCs are *served* as STIX 2.1 `indicator`; stored types also include the extra SCOs (`url`, `email-addr`, `ipv6-addr`, `mac-addr`, `windows-registry-key`, `autonomous-system`) and the SDO/SROs (`malware`, `threat-actor`, `campaign`, `report`, `identity`, `attack-pattern`, `vulnerability`, `relationship`). |
| `puller_state` | Per-community-puller delta state (`last_sync` feeds the poller's `?since=`) plus the last-run status shown in the dashboard. `id` is `otx` or `taxii:<name>`. |
| `subscriptions` | Legacy TAXII client subscriptions used by `POST /subscriptions/<client_id>` and `POST /auth`. |

### DDL (PostgreSQL)

```sql
CREATE TABLE stix_objects (
    id                 VARCHAR NOT NULL,          -- = stix_id (primary key)
    stix_id            VARCHAR NOT NULL,          -- unique STIX id (ingest key)
    object_type        VARCHAR NOT NULL,          -- ipv4-addr | domain-name | file-hash | indicator | report | ...
    name               VARCHAR,
    description        TEXT,
    labels             VARCHAR,                   -- comma-separated
    confidence         INTEGER,
    hash_value         VARCHAR,                   -- file hash
    ip_address         VARCHAR,                   -- IPv4
    domain             VARCHAR,                   -- FQDN
    value              VARCHAR,                   -- url / email / ipv6 / mac / registry-key / AS
    source_ref         VARCHAR,                   -- relationship source_ref
    target_ref         VARCHAR,                   -- relationship target_ref
    relationship_type  VARCHAR,
    object_refs        TEXT,                      -- report object_refs (JSON list)
    valid_from         TIMESTAMP,                 -- STIX valid_from (upstream, when known)
    collection_id      VARCHAR,                   -- which collection (multi-collection RBAC)
    source             VARCHAR,                   -- 'manual' | 'otx' | <puller name>
    first_seen         TIMESTAMP,
    last_seen          TIMESTAMP,
    revoked            BOOLEAN,
    revoked_at         TIMESTAMP,
    created            TIMESTAMP,
    modified           TIMESTAMP,                 -- drives ?since= / ?added_after= delta polling
    PRIMARY KEY (id)
);
CREATE INDEX        ix_stix_objects_object_type   ON stix_objects (object_type);
CREATE INDEX        ix_stix_objects_collection_id ON stix_objects (collection_id);
CREATE UNIQUE INDEX ix_stix_objects_stix_id       ON stix_objects (stix_id);

CREATE TABLE puller_state (
    id           VARCHAR NOT NULL,                -- 'otx' | 'taxii:<name>'
    last_sync    TIMESTAMP,                       -- feeds the poller's ?since=
    last_added   INTEGER,
    last_status  VARCHAR,                         -- 'ok' | 'error'
    last_message VARCHAR,
    updated_at   TIMESTAMP,
    PRIMARY KEY (id)
);

CREATE TABLE subscriptions (
    id            VARCHAR NOT NULL,
    client_id     VARCHAR NOT NULL,
    password_hash VARCHAR NOT NULL,
    enabled       BOOLEAN,
    created       TIMESTAMP,
    last_verified TIMESTAMP,
    PRIMARY KEY (id)
);
CREATE INDEX ix_subscriptions_client_id ON subscriptions (client_id);
```

> **Design notes.** There are **no foreign keys** — the store is deliberately
> flat/denormalised; STIX relationships are kept as `source_ref` / `target_ref`
> strings, not FK constraints. `labels` is a comma-joined string. `modified` is
> what the `?since=` / `?added_after=` delta-poll filter compares against, so it
> is rewritten on every upsert. `stix_id` is unique (that's what makes ingest an
> upsert, so the same value is never stored twice); `object_type` and
> `collection_id` are indexed for the collection- and type-filtered TAXII reads.

### Choose the database

| | SQLite (default) | PostgreSQL (recommended) | MariaDB/MySQL |
|---|---|---|---|
| Setup | none | create role + database | create database |
| Best for | dev / small single feed | **production** (read-heavy + concurrent writes) | if that's your standard |

### Path A — let the app create the schema (simplest)

```sql
-- run as a superuser
CREATE ROLE taxii LOGIN PASSWORD 'STRONG_PASSWORD';
CREATE DATABASE taxii_feed OWNER taxii;
```
```yaml
# config.yaml
database:
  url: postgresql+psycopg2://taxii:STRONG_PASSWORD@db-host:5432/taxii_feed
  pool_size: 5
  max_overflow: 10
  connection_timeout: 30
```
`pip install psycopg2-binary`, then start the app. `init_db()` creates the tables
(`CREATE TABLE IF NOT EXISTS …`) and applies any missing-column migrations; the
log shows `Database initialized`.

### Path B — DBA-managed (the app runs with DML rights only)

Pre-create the tables with the DDL above (as the owner), then grant the app role
data-only privileges:

```sql
GRANT CONNECT ON DATABASE taxii_feed TO taxii;
GRANT USAGE   ON SCHEMA public TO taxii;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO taxii;
```

> **Privileges caveat.** At startup the app also runs **idempotent column
> migrations** (`ALTER TABLE … ADD COLUMN` for `source`, `collection_id`,
> `value`, `object_refs`, `valid_from`, …) — but only for columns that are
> *missing*. If you pre-create the **complete** schema above, no `ALTER` is
> attempted and DML-only grants are sufficient. If a required column is absent
> and the role cannot `ALTER`, `init_db()` raises and the app will not start —
> so run once as the owner, or pre-create the full schema.

### Verify

```bash
psql "postgresql://taxii:***@db-host:5432/taxii_feed" -c '\dt'   # 3 tables + indexes
curl -s http://host:5000/health | jq '.database'                # "connected"
```

The same schema runs on **SQLite** (default, zero setup) and **MariaDB/MySQL** —
only `database.url` (and the pip driver) change. See the README's
[Choosing the database] section for the connection-string formats.

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
- **Backups**: `pg_dump taxii_feed > backup-$(date +%F).sql` (PostgreSQL) or copy the
  SQLite file; restore with `psql taxii_feed < backup.sql`.
- **Cleanup**: purge the feed with `DELETE /feed/purge` (or the dashboard *Purge all*).
  Dynamic indicators are auto-**revoked** by the TTL lifecycle rather than deleted, so
  growth is mostly bounded by the pollers' caps (`max_indicators_per_poll`, `limit`).
- **Indexes**: the schema ships with the indexes it needs (`stix_id` unique, `object_type`,
  `collection_id`). After large purges run `VACUUM ANALYZE` (PostgreSQL) / `VACUUM` (SQLite).
- Full schema, DDL and production setup: [Database Schema & Production Setup](#database-schema--production-setup).

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
