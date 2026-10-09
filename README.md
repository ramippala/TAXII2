# TAXII 2 Server for STIX 2.1 Threat Intelligence Feed

A standards-compliant **TAXII 2.1 server** (OASIS) that feeds custom threat
intelligence (IP addresses, file hashes, FQDNs) into **Trend Micro Vision One**.
Vision One is a TAXII 2.1 **client** — it polls this server's `/taxii2/`
collection (exactly how it consumes AlienVault OTX).

Optional background pullers (both off by default): an **AlienVault OTX**
community-intel puller (OTX → this server), and a `self_check` self-test.

An **intel filter** gates community-sourced intel before it is served to
Vision One (see [Intel Filter](#intel-filter-filtering-between-server-and-vision-one)).

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          TAXII Server Implementation                     │
│                                                                          │
│  ┌──────────────────────────┐   ┌──────────────────────────────────┐  │
│  │  Flask REST API          │   │  SQLite / In-Memory Store        │  │
│  │  (TAXII 2 + REST)        │   │  (STIX 2.1 objects)              │  │
│  │                          │   │                                   │  │
│  │  /feed                   │   │  - STIXObject (indicator, ipv4-  │  │
│  │  /feed/ingest            │   │    addr, file-hash, domain-name) │  │
│  │  /feed/purge             │   │  - Subscription                 │  │
│  │  /auth                   │   │  - OtxPoller (community pull)   │  │
│  │  /subscriptions          │   └──────────┬──────────────────────┘  │
│  │  /health                 │             │                            │
│  └──────────────────────────┘             ▼                            │
│                                                                          │
│  ┌──────────────────────────┐   ┌──────────────────────────────────┐  │
│  │  OTX Community Puller    │   │  TAXII 2 Client (optional)      │  │
│  │  (pull FROM OTX)         │   │  - TAXII feed retrieval         │  │
│  │                          │   └──────────────────────────────────┘  │
│  │  GET /otxapi/pulses/...  │                                             │
│  └──────────────────────────┘                                             │
└─────────────────────────────────────────────────────────────────────────┘
                              ▲
                              │
                    ┌─────────────────────┐
                    │  AlienVault OTX     │
                    │  (community intel   │
                    │   source, pulled)   │
                    └─────────────────────┘
```

### Components

1. **Flask REST API (TAXII 2 Server)** — Hosts TAXII 2.1 protocol endpoints and custom REST endpoints for feed management, auth, subscriptions, and health.
2. **STIX 2.1 Store** — Stores threat intelligence objects (IPs, file hashes, domains, indicators) in SQLite with an in-memory store for fast polling. Every object carries a `source` tag (`manual` vs `otx`) so manual and community intel coexist.
3. **OTX Community Puller** — Background thread that periodically pulls indicators (IPv4, domains, file hashes) from **AlienVault OTX** public pulses and merges them into the feed tagged `source='otx'`. Off by default.
4. **Self-check Poller** — Background thread that periodically fetches the local `/feed` endpoint to verify the feed is reachable and well-formed. Off by default.

> **Data flow:** `AlienVault OTX ──pull──▶ this server ──intel filter──▶ Vision One`.
> The **intel filter** gates community-sourced objects before they are served
> over `/taxii2/`, to cut false positives (manual intel always passes).
> There is no Trend Micro SOL puller anymore — this server does not pull from
> Trend Micro.

## Installation

### Prerequisites

- **Python 3.10+** (tested on 3.11)
- Virtual environment (recommended)
- No other third-party dependencies beyond those listed below

### Step 1: Install Dependencies

```bash
cd /home/gojo/code/TAXII
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

Dependencies:

| Package | Purpose |
|---------|---------|
| Flask 3.0.0 | Web framework for REST API |
| flask-cors 4.0.0 | CORS support |
| SQLAlchemy 2.0.18 | ORM / database |
| Werkzeug 3.0.2 | Password hashing & URL utilities |
| pyyaml 6.0.1 | Configuration (YAML) |
| psycopg2-binary *(optional)* | PostgreSQL driver — only if you use a Postgres `database.url` |
| PyMySQL *(optional)* | MariaDB/MySQL driver — only if you use a MySQL `database.url` |

> SQLite (the default) needs no driver. Install one of the optional drivers
> only when you switch `database.url` to PostgreSQL or MariaDB.

### Choosing the database

| | SQLite (default) | PostgreSQL (recommended) | MariaDB/MySQL |
|---|---|---|---|
| Setup | None | `createdb taxii_feed` | `CREATE DATABASE taxii_feed` |
| Concurrent read + write | Single writer (file lock) | MVCC — readers never block the writer | Good (InnoDB MVCC) |
| Best for | Dev / single small feed | **Production** | Production (if that's your standard) |

**Recommendation: PostgreSQL.** This server is read-heavy while being written —
Vision One polls the collection (full reads) at the same time the SOL poller /
your ingests write. Postgres MVCC handles that cleanly, its indexed
`modified` range scan keeps `?since=` delta polling fast at scale, and it has
the strongest JSON support (`JSONB`) if you later want to store raw STIX
objects and query them.

**MariaDB** is a solid second choice if your environment standardizes on it.

**Switching from SQLite → PostgreSQL (3 steps):**

```bash
# 1. Install the driver
pip install psycopg2-binary

# 2. Create the DB + user
sudo -u postgres psql -c "CREATE ROLE taxii LOGIN PASSWORD 'CHANGE_ME';" \
                       -c "CREATE DATABASE taxii_feed OWNER taxii;"

# 3. Point config.yaml at it (tables are created automatically on first start)
```

```yaml
database:
  url: postgresql+psycopg2://${DB_USER:-taxii}:${DB_PASS:-CHANGE_ME}@${DB_HOST:-localhost}:5432/${DB_NAME:-taxii_feed}
  pool_size: 5
  max_overflow: 10
  connection_timeout: 30
```

Then restart the server — `Base.metadata.create_all` builds the tables for
you. (For a real migration of existing SQLite data, export/import the
`stix_objects` rows; the schema is identical.)

### Step 2: Configure

Edit `config.yaml` with your settings:

```yaml
server:
  host: '0.0.0.0'
  port: 5000
  debug: false
  cors_origins: ['*']

database:
  # Dev default: in-process SQLite (zero setup). For production, point this at
  # PostgreSQL (recommended) or MariaDB — see the `database:` block in
  # config.yaml for the exact URL format + driver to pip install.
  url: sqlite:///taxii_feed.db

security:
  secret_key: ${FLASK_SECRET:-dev-secret-key-change-in-production}

taxii:
  collection_id: 'threat-intel'          # collection Vision One polls
  # TAXII client credentials (HTTP Basic) — Vision One is configured with these
  auth:
    username: 'your-taxii-username'
    password: 'your-taxii-password'

otx:
  enabled: false        # set true to start pulling community intel from OTX
  base_url: 'https://otx.alienvault.com'
  api_key: ''           # optional free OTX API key (raises rate limits)
  poll_interval: 300    # 5 min polling interval
  max_pulses: 25
  object_types: ['ipv4-addr', 'domain-name', 'file-hash']
```

> `${ENV_VAR:-default}` placeholders in config values are resolved from the
> environment at startup.

### Step 3: Run the Server

```bash
./venv/bin/python server.py
```

The server starts on `http://0.0.0.0:5000` by default. Pollers only start
when their `enabled` flag is `true` and a real `base_url` is configured.

## Feeding Intel: Web UI (no curl needed)

Start the server and open **`http://localhost:5000/`** (or `/ui`) in a browser.

The **TAXII Feed Manager** lets you:
1. Enter the server URL + TAXII username/password (the `taxii.auth` values) and hit **Connect**.
2. **Load current feed** — pulls what's already in the feed into an editable table.
3. **Add new entry** — pick a type (IPv4 / domain / file hash / indicator), type the value.
   IDs and hash algorithms (MD5/SHA-1/SHA-256) are auto-derived, and values are validated.
4. **Save feed (replace)** — publishes the checked rows. Because ingest is
   *replace-all*, load first and uncheck rows you want to drop (this is how you
   "delete" an entry).
5. **Purge all** — wipes the feed with a confirmation.

Each loaded row shows a **source badge** (`manual` / `otx`) and a **gate
badge** (`served` / `withheld`). A separate **"Withheld by filter"** panel
lists every community object the [intel filter](#intel-filter-filtering-between-server-and-vision-one)
is keeping out of Vision One, with the exact **reason** (Private / reserved
IP, Stale, Low confidence, or Blocklisted). These objects are still stored —
nothing is deleted; loosening the matching rule in `config.yaml`
(`intel_filter:`) and restarting releases them.

The UI is a single self-contained `intel-ui.html` (no CDN/JS dependencies, works offline),
served directly by the Flask app. Credentials are sent only as `X-Taxii-*` headers to the
configured server.

## Feeding Intel: API (curl)

### GET /feed

Returns the latest STIX feed in **TAXII 2 XML** format.

**Authentication:** requires TAXII credentials from `taxii.auth` in
`config.yaml`, sent either as `X-Taxii-Username` / `X-Taxii-Password`
headers or HTTP Basic auth. Unauthenticated requests get `401`.

**Request:**
```bash
curl http://localhost:5000/feed \
  -H "X-Taxii-Username: your-taxii-username" \
  -H "X-Taxii-Password: your-taxii-password"
```

**Response:**
```xml
<Response xmlns="stix-taxon" xmlns:v2_1="http://cyclonedx.org/schema/cyclonedx/1.3">
  <body>
    <v2_1>
      <bundle id="Bundle-1717840000">
        <objects>
          <object id="ipv4-addr--123" type="ipv4-addr">
            <properties><value>192.168.1.100</value></properties>
          </object>
          <object id="file-hash--abc123" type="file-hash">
            <properties>
              <hash_value><algorithm>sha256</algorithm><value>a1b2…</value></hash_value>
            </properties>
          </object>
        </objects>
      </bundle>
    </v2_1>
  </body>
</Response>
```

**Use:** This is the TAXII 2 feed that Trend Micro clients poll.

### POST /feed/ingest

Accepts STIX 2.1 JSON objects and replaces the in-memory feed.

**Request Body:**
```json
{
  "stix_objects": [
    {
      "id": "ipv4-addr--123",
      "type": "ipv4-addr",
      "object": {"ipv4-addr": {"value": "192.168.1.100"}},
      "labels": ["threat", "malicious"],
      "confidence": 80
    },
    {
      "id": "domain-name--789",
      "type": "domain-name",
      "object": {"domain-name": {"value": "malicious.example.com"}},
      "labels": ["threat", "malicious"],
      "confidence": 65
    },
    {
      "id": "file-hash--abc123",
      "type": "file-hash",
      "object": {
        "hash_value": {
          "algorithm": "sha256",
          "value": "a" * 64
        }
      },
      "labels": ["sha256", "malware"],
      "confidence": 75
    }
  ]
}
```

**Response:**
```json
{
  "message": "Data ingested successfully",
  "objects_count": 3
}
```

### DELETE /feed/purge

Purges all threat intelligence data from memory and database.

### GET /subscriptions

Lists all active TAXII subscriptions.

### POST /subscriptions/<client_id>

Creates a new subscription.

**Request Body:**
```json
{
  "password": "secure-password"
}
```

**Response:**
```json
{
  "message": "Subscription created",
  "client_id": "trendmicro-client",
  "id": "trendmicro-client@a1b2c3d4"
}
```

### POST /auth

Authenticates a client (form-encoded) against its **stored subscription** —
the client must first be registered via `POST /subscriptions/<client_id>`.
Returns `401` if the client is unknown or the password does not match.

**Request:**
```
POST /auth
Content-Type: application/x-www-form-urlencoded
username=your-username&password=your-password
```

### GET /health

Health check endpoint for monitoring.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2026-10-07T10:30:00",
  "objects_count": 42,
  "database": "connected",
  "poller": {"otx": "stopped", "self_check": "stopped"}
}
```

## Trend Micro Vision One Integration Guide

### How the protocol works

Trend Micro **Vision One is a TAXII 2.1 client**. It polls a **TAXII 2.1
server** (this is exactly how it consumes e.g. AlienVault OTX — a standards-
compliant TAXII 2.1 server). So this server exposes a **standards-compliant
TAXII 2.1 API** under `/taxii2/`, and Vision One is pointed at it. This was
validated against the official OASIS `taxii2-client` reference implementation:
discovery → collections → get-objects all pass.

> The old `/feed` (custom XML) and `/objects` (JSON) endpoints remain for the
> web UI and scripting, but **Vision One uses `/taxii2/`**, not `/feed`.

### Step 1: Configure the server

```yaml
taxii:
  collection_id: 'threat-intel'      # the collection Vision One polls
  collection_title: 'Custom Threat Intelligence Feed'
  auth:
    username: 'admin'                 # TAXII client username
    password: 'admin'                 # TAXII client password
```

### Step 2: Feed intel

Add objects via the web UI (`http://<server>:5000/`) or `POST /feed/ingest`.
They are stored in the database and served from the TAXII collection.

### Step 3: Point Vision One at this server

In Vision One, create a TAXII 2.1 data source / feed subscription:

| Field | Value |
|-------|-------|
| **URL / Endpoint** | `http://<this-server>:5000/taxii2/` |
| **Protocol** | TAXII 2.1 |
| **Collection** | `threat-intel` |
| **Username** | `admin` (from `taxii.auth`) |
| **Password** | `admin` (from `taxii.auth`) |
| **Poll interval** | 15–30 minutes |
| **Object types** | IPv4, domain, file hash (indicator) |

The client does: discover `/taxii2/` → list `/taxii2/collections/` → poll
`/taxii2/collections/threat-intel/objects/`, receiving a STIX 2.1 JSON bundle
wrapped in a TAXII 2.1 message.

### TAXII 2.1 endpoints exposed

| Endpoint | Purpose |
|----------|---------|
| `GET /taxii2/` | API Root + Server Discovery |
| `GET /taxii2/collections/` | List collections |
| `GET /taxii2/collections/<id>/` | Collection info (`can_read`) |
| `GET /taxii2/collections/<id>/objects/` | **Poll STIX 2.1 objects** (supports `?since=`) |
| `POST /taxii2/collections/<id>/objects/` | Add-objects ack (read-only feed → no-op) |
| `GET /taxii2/status/<id>/` | Status (reports `complete`) |
| `GET /taxii2/subscriptions/` | Subscription list (empty) |

Auth is **HTTP Basic** (the TAXII standard) — the same `taxii.auth`
credentials. `?since=<ISO8601>` returns only objects modified after that
timestamp, enabling efficient delta polling.

### Verifying it works (without Vision One)

```bash
# 1. Discover the API root
curl -u admin:admin http://localhost:5000/taxii2/

# 2. Poll objects (raw TAXII 2.1 message envelope)
curl -u admin:admin http://localhost:5000/taxii2/collections/threat-intel/objects/

# 3. With the official OASIS reference client (recommended)
python -c "from taxii2client import ApiRoot; r=ApiRoot('http://localhost:5000/taxii2/',user='admin',password='admin'); r.refresh_collections(); print(r.collections[0].get_objects())"
```

### Optional background pollers (both off by default)

These two are *not* how Vision One works — Vision One polls `/taxii2/` on its
own (see Step 3). They are optional helpers:

- **`otx`** — pulls community threat intel **from AlienVault OTX** (public
  pulses / indicators) into the feed. It lists recently-updated public pulses,
  maps their IPv4 / domain / file-hash indicators to STIX objects, and merges
  them in tagged `source='otx'` — so it never wipes your manual/web-UI intel,
  and a web-UI save never wipes OTX intel. To enable, set `otx.enabled: true`
  in `config.yaml` (an optional free `api_key` raises OTX rate limits).
- **`self_check`** — a self-test that polls this server's *own* `/feed`
  endpoint to confirm it stays reachable. (Previously misnamed `vision_one`;
  that name has been dropped, but old `vision_one:` configs still work.)

> **Note on ingest modes.** `POST /feed/ingest` (web UI / manual) uses
> *replace* mode scoped to `source='manual'`. The OTX puller uses *merge*
> mode (upsert by STIX id, append-only). This keeps your hand-fed intel and
> pulled community intel independent of each other.

## Intel Filter (filtering between server and Vision One)

A read-time **gate** sits in front of the `/taxii2/` collection Vision One
polls. Its job is to **reduce false positives** and give you control over
which community intel actually reaches Vision One:

```
AlienVault OTX ──pull──▶ this server ──[intel filter]──▶ Vision One
```

Key properties:

- **Community data only.** It applies to objects whose `source` is in
  `intel_filter.community_sources` (default `['otx']`). Your manually-fed
  intel (web UI / `POST /feed/ingest`, `source='manual'`) **always passes**.
- **Vision One feed only.** It is enforced on the `/taxii2/` objects endpoint.
  The web UI (`GET /objects`) still shows *all* stored intel, so you can see
  and manage everything — including objects the gate is withholding.
- **Read-time, not destructive.** Every object stays in the database
  (auditable). The filter only decides what is *served*; nothing is deleted,
  so it is fully reversible (flip a toggle, restart, and the object is served
  again).

### The four rules (all config toggles in `intel_filter:`)

| Rule | Config key | Default | Withholds a community object when… |
|------|-----------|---------|------------------------------------|
| Private/reserved IPs | `drop_private_ips` | `true` | The IP is non-routable / special-use: `10/8`, `172.16/12`, `192.168/16`, `127/8`, `169.254/16`, `0/8`, `240/4`, IPv4-mapped v6, CGNAT, IANA reserved. These dominate OTX honeypot feeds. |
| Freshness window | `freshness_days` | `30` | `last_seen`/`modified` is older than N days (stale). Set `null` to disable. |
| Confidence floor | `min_confidence` | `null` (off) | Confidence is below the floor. OTX community objects default to `70`. |
| Value blocklist | `blocklist` | `[]` (off) | The exact value (IP / domain / hash / name, case-insensitive) is listed. |

A community object is withheld if it trips **any** active rule. When an
object is withheld, the server logs e.g. `Intel gate withheld N community
object(s) from the TAXII feed`.

### Example config

```yaml
intel_filter:
  community_sources: ['otx']     # which source tags are "community" (gated)
  drop_private_ips: true         # drop non-routable IPs (biggest noise reducer)
  freshness_days: 30             # drop community intel older than 30 days
  min_confidence: null           # set e.g. 80 to enforce a confidence floor
  blocklist: []                  # e.g. ['example.com', '198.51.100.20']
```

> **Blocklist note:** the blocklist matches **single exact values** (not CIDR
> ranges) — `10.20.30.40` matches that IP, but `10.20.0.0/16` does *not*
> expand to a range. The `drop_private_ips` rule already covers the whole
> private space; use the blocklist for specific *public* values you always
> want to exclude.

## Testing

Run the test suite:

```bash
python tests/test_server.py
```

This covers all TAXII 2.1 endpoints, ingestion (replace + merge modes),
authentication, subscription management, STIX conversion, TAXII bundle
generation, the OTX poller (init, URL/headers, indicator mapping, and
manual-vs-OTX source isolation), and the intel gate (private-IP drop,
freshness, confidence floor, blocklist, and that manual intel is never gated).

## Security Considerations

- Use **HTTPS/TLS** for production deployments (configurable via reverse proxy).
- Use strong, unique passwords and store them hashed.
- Set `SECRET_KEY` or `FLASK_SECRET` environment variable.
- Set `debug: false` in production.
- Rate-limit ingestion requests if needed.
- Disable CORS (`flask_cors`) only for trusted origins.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TAXII_CONFIG` | `./config.yaml` | Path to configuration file |
| `FLASK_SECRET` | `dev-secret-key-change-in-production` | Flask secret key |
| `DATABASE_URL` | `sqlite:///taxii_feed.db` | Database connection URL |

## Troubleshooting

### Server won't start

1. Verify Python 3.10+ is installed.
2. Confirm `pip install -r requirements.txt` completed.
3. Check `config.yaml` paths are correct.
4. Check port 5000 is not in use.

### Ingestion fails

- Verify STIX object `type` is one of: `ipv4-addr`, `file-hash`, `domain-name`, `indicator`, `malware`, `malware-family`.
- Ensure `id` follows STIX ID conventions (e.g., `ipv4-addr--123`, `file-hash--abcdef123`).
- Check `object` structure matches the expected type.

### OTX poller doesn't receive data

- Confirm `otx.enabled: true` and `otx.base_url` is `https://otx.alienvault.com`.
- Add a free `otx.api_key` (from otx.alienvault.com) if you hit OTX rate limits.
- Check `max_pulses`, `max_indicators_per_pulse`, and `object_types` — if a
  pulse only contains indicator types you've excluded (e.g. URL/YARA), nothing
  is ingested for it.
- Verify the polling interval is not too aggressive (avoid rate-limit blocks).
- OTX data is community-sourced; a `429`/timeout is logged and the cycle
  retries on the next interval.

### Community intel is in the DB but Vision One isn't getting it

- The **intel filter** is withholding it. Check the server log for
  `Intel gate withheld N community object(s)`. Then review `intel_filter`:
  a private IP trips `drop_private_ips`, an old object trips
  `freshness_days`, a low-confidence one trips `min_confidence`, and a
  listed value trips `blocklist`.
- The web UI still shows the object (the gate only affects the `/taxii2/`
  feed), so you can confirm it's *stored* but *withheld*. Loosen the relevant
  toggle (or add nothing / remove a blocklist entry), restart, and it's
  served again — nothing was deleted.

## License

MIT License
