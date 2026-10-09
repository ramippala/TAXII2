# TAXII 2 Server for STIX 2.1 Threat Intelligence Feed

A standards-compliant **TAXII 2.1 server** (OASIS) that feeds custom threat
intelligence (IP addresses, file hashes, FQDNs) into **Trend Micro Vision One**.
Vision One is a TAXII 2.1 **client** — it polls this server's `/taxii2/`
collection (exactly how it consumes AlienVault OTX).

The **web UI dashboard** (`http://<server>:5000/`) is **login-protected**
(`ui.auth` in `config.yaml`). After login you can add intel manually and
watch/control **community sources**: the optional **AlienVault OTX** puller
plus any number of **third-party TAXII 2.1 pullers** you define under
`taxii_pullers:` (each with a "Pull now" button, even while disabled).

An **intel filter** gates community-sourced intel before it is served to
Vision One (see [Intel Filter](#intel-filter-filtering-between-server-and-vision-one)).

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          TAXII Server Implementation                     │
│                                                                          │
│  ┌──────────────────────────┐   ┌──────────────────────────────────┐  │
│  │  Flask REST API          │   │  SQLite / In-Memory Store        │  │
│  │  (TAXII 2 + REST)        │   │  (STIX 2.1 objects, each tagged  │  │
│  │                          │   │   with its source)               │  │
│  │  / (web UI, login-guard) │   │  - STIXObject (indicator, ipv4-  │  │
│  │  /ui/login|session|logout│   │    addr, file-hash, domain-name) │  │
│  │  /objects  /feed/ingest  │   │  - Subscription                 │  │
│  │  /community/pullers|pull │   │  - PullerState (last sync per    │  │
│  │  /taxii2/  (gate applied)│   │    community source)            │  │
│  │  /health                 │   └──────────┬───────────────────────┘  │
│  └──────────────────────────┘             │                            │
│                                                                          │
│  ┌──────────────────────────┐   ┌──────────────────────────────────┐  │
│  │  OTX Community Puller    │   │  Third-party TAXII 2.1 Pullers   │  │
│  │  (pull FROM OTX, merge,  │   │  (pull FROM any TAXII server,    │  │
│  │   source='otx')          │   │   merge, source=<puller name>)   │  │
│  └──────────────────────────┘   └──────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
                              ▲
                              │
             ┌────────────────┴────────────────┐
             │  AlienVault OTX / any TAXII    │
             │  2.1 server (community intel)  │
             └────────────────────────────────┘
```

### Components

1. **Flask REST API (TAXII 2 Server)** — Hosts TAXII 2.1 protocol endpoints and custom REST endpoints for feed management, UI login/session, community-source control, auth, subscriptions, and health.
2. **Web UI dashboard** — Single self-contained `intel-ui.html` behind a login (`ui.auth`). Shows the current feed with per-row **source** and **gate** badges, a **withheld-by-filter** panel, a **community sources** panel (status + "Pull now"), and manual intel entry/publish. Serves all intel (the gate only affects what Vision One gets).
3. **STIX 2.1 Store** — Stores threat intelligence objects (IPs, file hashes, domains, indicators) in SQLite with an in-memory store for fast polling. Every object carries a `source` tag (`manual` | `otx` | a `taxii_pullers` name) so manual and community intel coexist. Puller sync state (`last_sync`, `last_added`) is persisted in a `puller_state` table so delta pulls survive restarts.
4. **OTX Community Puller** — Background thread that periodically pulls indicators (IPv4, domains, file hashes) from **AlienVault OTX** public pulses and merges them into the feed tagged `source='otx'`. Off by default; can also be fired on demand from the UI.
5. **Third-party TAXII 2.1 Pullers** — One generic puller per `taxii_pullers:` entry. Polls `GET {api_root}collections/{collection}/objects/?since=` from any TAXII 2.1 server (Basic auth, `application/taxii+json;version=2.1`), maps STIX 2.1 objects into the feed in merge mode tagged with the puller's `name`. Off by default per entry.
6. **Self-check Poller** — Background thread that periodically fetches the local `/feed` endpoint to verify the feed is reachable and well-formed. Off by default.

> **Data flow:** `OTX / third-party TAXII servers ──pull──▶ this server ──intel filter──▶ Vision One`.
> The **intel filter** gates community-sourced objects before they are served
> over `/taxii2/`, to cut false positives (manual intel always passes).
> There is no Trend Micro SOL puller — this server does not pull from
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

# Web UI dashboard login (SEPARATE from taxii.auth above)
ui:
  auth:
    username: 'admin'
    password: 'admin'
  session_ttl: 43200        # UI session lifetime, seconds (default 12 h)

otx:
  enabled: false        # set true to start pulling community intel from OTX
  base_url: 'https://otx.alienvault.com'
  api_key: ''           # optional free OTX API key (raises rate limits)
  poll_interval: 300    # 5 min polling interval
  max_pulses: 25
  object_types: ['ipv4-addr', 'domain-name', 'file-hash']

# Third-party TAXII 2.1 pullers (empty = none). See Community Sources.
taxii_pullers: []
  # - name: otx-taxii
  #   base_url: https://otx.alienvault.com/taxii2/
  #   username: 'your-otx-api-key'
  #   password: ''
  #   collection: 'threat-intel'
  #   poll_interval: 300
  #   max_objects_per_poll: 5000
  #   enabled: false
```

> `${ENV_VAR:-default}` placeholders in config values are resolved from the
> environment at startup.

### Step 3: Run the Server

```bash
./venv/bin/python server.py
```

The server starts on `http://0.0.0.0:5000` by default. Pollers only start
when their `enabled` flag is `true` and a real `base_url` is configured.

## Feeding Intel: Web UI (login → dashboard)

Start the server and open **`http://localhost:5000/`** (or `/ui`) in a
browser. You'll be shown a **login card** — enter the `ui.auth` credentials
from `config.yaml` (default `admin` / `admin`) and click **Login**. This sets
an http-only session cookie (`taxii2_ui_session`); subsequent UI requests
authenticate with it, so you don't re-enter anything until it expires
(`ui.session_ttl`, default 12 h) or you click **Log out**.

> **UI login ≠ TAXII credentials.** `ui.auth` is for *this dashboard only*.
> `taxii.auth` is what **Vision One** (and scripts/curl) uses to poll
> `/taxii2/`. They are independent and can be different values. The data
> endpoints (`/objects`, `/feed/ingest`, `/feed/purge`, `/community/*`)
> accept **either** the UI session cookie **or** the TAXII credentials
> (`X-Taxii-*` headers or HTTP Basic), so curl workflows keep working.

Once logged in, the **TAXII Feed Manager** dashboard lets you:

1. **Current feed** — an editable table of everything in the feed. Each row
   shows a **source badge** (`manual` / `otx` / a puller name), a **gate
   badge** (`served` / `withheld`, with the reason on hover), and a
   **Status** cell (`active` / `revoked`) with a **Revoke / Unrevoke** button
   for marking false positives.
2. **Add new entry** — pick a type (IPv4 / domain / file hash / indicator),
   type the value. IDs and hash algorithms (MD5/SHA-1/SHA-256) are
   auto-derived, and values are validated.
3. **Save feed (replace)** — publishes the checked rows. Because manual ingest
   is *replace* scoped to `source='manual'`, it only affects your manual
   intel — community (pulled) intel is untouched. Load first and uncheck rows
   you want to drop.
4. **Purge all** — wipes the feed with a confirmation.
5. **Withheld by filter** — a panel listing every community object the
   [intel filter](#intel-filter-filtering-between-server-and-vision-one) is
   keeping out of Vision One, with the exact **reason** (Private / reserved
   IP, Stale, Low confidence, or Blocklisted). These objects are still stored
   — nothing is deleted; loosening the matching rule in `config.yaml`
   (`intel_filter:`) and restarting releases them.
6. **Community sources** — a table of the OTX puller plus each
   `taxii_pullers:` entry (kind, enabled/running, last sync, last added,
   status) with a **Pull now** button. "Pull now" runs one fetch on demand
   (it works even while a puller is `enabled: false`, for a one-shot fetch),
   then refreshes the feed table. See
   [Community Sources](#community-sources-pulling-from-otx-or-any-taxii-21-server).
7. **Import CSV (GT team)** — upload a `.csv` with any headers (fuzzy-mapped
   to IPv4 / domain / file hash / indicator); appends to the manual feed. See
   [CSV import](#3-csv-import-gt-team-ad-hoc-intel).

The UI is a single self-contained `intel-ui.html` (no CDN/JS dependencies,
works offline), served directly by the Flask app. The browser talks to the
server over same-origin requests carrying the session cookie.

## Feeding Intel: API (curl)

### GET /feed

Returns the latest STIX feed in **TAXII 2 XML** format.

**Authentication:** the data endpoints (`/feed`, `/objects`,
`/feed/ingest`, `/feed/purge`, `/community/*`) require credentials — either
the TAXII credentials from `taxii.auth` in `config.yaml` (sent as
`X-Taxii-Username` / `X-Taxii-Password` headers or HTTP Basic), **or** a valid
UI session cookie (from the dashboard login). Unauthenticated requests get
`401`. For curl, use the TAXII credentials:

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

### UI session endpoints

These drive the dashboard login. They are independent of `taxii.auth`.

| Endpoint | Purpose |
|----------|---------|
| `GET /ui/session` | Current session: `{"authenticated": bool, "user": str\|null}` |
| `POST /ui/login` | Body `{"username","password"}` checked against `ui.auth`. On success sets the http-only `taxii2_ui_session` cookie (signed with `security.secret_key`, lifetime `ui.session_ttl`); `401` on bad credentials. |
| `POST /ui/logout` | Deletes the session cookie. |

### Object lifecycle endpoints

| Endpoint | Purpose |
|----------|---------|
| `POST /objects/<stix_id>/revoke` | Body `{"action":"revoke"}` (default) or `{"action":"unrevoke"}`. Sets/clears the STIX `revoked` flag. A revoked object stays stored and is served to Vision One with `revoked: true` so it can be purged. `404` if the id is unknown, `400` on a bad action. |

### CSV import endpoint

| Endpoint | Purpose |
|----------|---------|
| `POST /feed/import-csv` | GT-team ad-hoc intel. Multipart `file` field (UI) or raw CSV body. Fuzzy header → type mapping, per-value validation, merge (append) as `source='manual'`. Returns `{imported, skipped[], skipped_total}`. `400` if nothing recognizable. See [CSV import](#3-csv-import-gt-team-ad-hoc-intel). |

### Community source endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /community/pullers` | Status of all community sources: the OTX puller plus each `taxii_pullers:` entry (`name`, `kind`, `enabled`, `running`, `base_url`, `collection` for TAXII, `last_sync`, `last_added`, `last_status`, `last_message`). |
| `POST /community/pull/otx` | Run one OTX pull cycle now (the UI "Pull now"). Returns `{name, added, error, last_sync, last_status}`. |
| `POST /community/pull/<name>` | Run one pull cycle now for a `taxii_pullers:` entry named `<name>`. `404` if unknown, `400` if misconfigured. Works even when the puller is `enabled: false` (one-shot fetch). |

> "Pull now" runs **synchronously in the request** (up to ~30 s of external
> HTTP per call). Enable a puller's background polling with its `enabled:
> true`; use "Pull now" for on-demand fetches.

### GET /health

Health check endpoint for monitoring.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2026-10-07T10:30:00",
  "objects_count": 42,
  "database": "connected",
  "poller": {
    "otx": "stopped",
    "self_check": "stopped",
    "taxii": {"otx-taxii": "running"}
  }
}
```

`poller.taxii` is a map of puller `name` → `running`/`stopped` (empty `{}`
when no `taxii_pullers:` entries are configured).

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
| `GET /taxii2/collections/<id>/objects/` | **Poll STIX 2.1 objects** (supports `?since=`/`?added_after=`, `?match[type]=`, `?match[id]=`) |
| `POST /taxii2/collections/<id>/objects/` | Add-objects ack (read-only feed → no-op) |
| `GET /taxii2/status/<id>/` | Status (reports `complete`) |
| `GET /taxii2/subscriptions/` | Subscription list (empty) |

Auth is **HTTP Basic** (the TAXII standard) — the same `taxii.auth`
credentials. `?since=<ISO8601>` (alias `?added_after=`) returns only objects
modified after that timestamp, enabling efficient delta polling. Standard
TAXII 2.1 filtering is also supported:

```bash
# only domains
curl -u admin:admin 'http://localhost:5000/taxii2/collections/threat-intel/objects/?match[type]=domain-name'
# only specific objects
curl -u admin:admin 'http://localhost:5000/taxii2/collections/threat-intel/objects/?match[id]=domain-name--evil-example-com'
```

> **Revoked objects** are included in the bundle with `revoked: true` (see
> [Indicator Lifecycle](#indicator-lifecycle-ttl--revocation)) so clients can
> purge them — they are never silently omitted.

### Verifying it works (without Vision One)

```bash
# 1. Discover the API root
curl -u admin:admin http://localhost:5000/taxii2/

# 2. Poll objects (raw TAXII 2.1 message envelope)
curl -u admin:admin http://localhost:5000/taxii2/collections/threat-intel/objects/

# 3. With the official OASIS reference client (recommended)
python -c "from taxii2client import ApiRoot; r=ApiRoot('http://localhost:5000/taxii2/',user='admin',password='admin'); r.refresh_collections(); print(r.collections[0].get_objects())"
```

### Optional background pollers (all off by default)

These are *not* how Vision One works — Vision One polls `/taxii2/` on its
own (see Step 3). They are optional helpers (all off by default):

- **`otx`** — pulls community threat intel **from AlienVault OTX** (public
  pulses / indicators) into the feed. It lists recently-updated public pulses,
  maps their IPv4 / domain / file-hash indicators to STIX objects, and merges
  them in tagged `source='otx'` — so it never wipes your manual/web-UI intel,
  and a web-UI save never wipes OTX intel. To enable, set `otx.enabled: true`
  in `config.yaml` (an optional free `api_key` raises OTX rate limits).
- **`taxii_pullers:`** — one or more generic pullers that fetch STIX 2.1
  objects **from any third-party TAXII 2.1 server**, merged in tagged with
  the puller's `name`. See [Community Sources](#community-sources-pulling-from-otx-or-any-taxii-21-server).
- **`self_check`** — a self-test that polls this server's *own* `/feed`
  endpoint to confirm it stays reachable. (Previously misnamed `vision_one`;
  that name has been dropped, but old `vision_one:` configs still work.)

> **Note on ingest modes.** `POST /feed/ingest` (web UI / manual) uses
> *replace* mode scoped to `source='manual'`. The OTX and TAXII pullers use
> *merge* mode (upsert by STIX id, append-only). This keeps your hand-fed
> intel and pulled community intel independent of each other.

## Indicator Lifecycle (TTL & revocation)

Dynamic indicators age out and are withdrawn cleanly instead of vanishing,
so Vision One always sees the truth about what it should be matching.

### Auto-revocation (per-type TTL)

Configured under `lifecycle:` (see `config.yaml`). A background sweeper
(default every `sweep_interval` seconds, plus one sweep at startup) scans for
objects older than their **per-type TTL** (measured from `last_seen`,
falling back to `first_seen`/`modified`) and **revokes** them:

| Type | Default TTL | Rationale |
|------|------------|-----------|
| `ipv4-addr` | 14 days | IPs are dynamic — rotate fast |
| `domain-name` | 30 days | FQDNs — medium |
| `file-hash` | 180 days | Hashes are stable — long |
| `indicator` | 30 days | free-form / pattern |

A revoked object is **not deleted** — it stays in the DB and is still *served*
to Vision One, but now with `revoked: true`. TAXII clients use that flag to
**purge** the indicator from their side, which is exactly how a false positive
gets cleaned up everywhere at once. Set `lifecycle.enabled: false`, or a type's
days to `null`, to disable (per type or globally).

> **Revoked vs gated.** The [intel filter](#intel-filter-filtering-between-server-and-vision-one)
> *withholds* an object entirely (it is not served). TTL **revokes** an object
> (it is served, but flagged). A community object can be gated *or* revoked;
> the gate is checked first.

### Manual revocation (false positives)

From the dashboard: each feed row has a **Status** column with a
**Revoke / Unrevoke** button. Or via API:

```bash
# Mark an object as a false positive / clean (served to Vision One as revoked: true)
curl -X POST http://localhost:5000/objects/ipv4-addr--1-2-3-4/revoke \
  -u admin:admin -H 'Content-Type: application/json' -d '{"action":"revoke"}'

# Reinstate it later
curl -X POST http://localhost:5000/objects/ipv4-addr--1-2-3-4/revoke \
  -u admin:admin -H 'Content-Type: application/json' -d '{"action":"unrevoke"}'
```

Revocation is **sticky**: it survives a web-UI *replace* save (a save that
doesn't explicitly set `revoked` won't silently reinstate it). Only an
explicit `unrevoke` clears it.

## Community Sources (pulling from OTX or any TAXII 2.1 server)

This is the **ingest side** of the pipeline — how community intel gets *into*
this server (Vision One only ever reads it out via `/taxii2/`). There are two
kinds, both shown in the **Community sources** dashboard panel:

### 1. AlienVault OTX (built-in)

Configured under `otx:` (see the block in `config.yaml`). `enabled: false` by
default. Pulls public pulse indicators (IPv4 / domain / file hash) and merges
them in tagged `source='otx'`. An optional free `api_key` raises rate limits.

### 2. Third-party TAXII 2.1 servers (`taxii_pullers:`)

Add one entry per source under `taxii_pullers:` in `config.yaml`. Each is a
self-contained puller that polls a remote TAXII 2.1 collection with Basic
auth and `Accept: application/taxii+json;version=2.1`:

```yaml
taxii_pullers:
  - name: otx-taxii              # doubles as the object `source` tag + UI label
    base_url: https://otx.alienvault.com/taxii2/
    username: 'your-otx-api-key' # OTX uses the API key as the username
    password: ''
    collection: 'threat-intel'
    poll_interval: 300           # seconds between background polls
    max_objects_per_poll: 5000
    enabled: false               # true to poll in the background
```

- **`name`** is required and unique — it becomes the `source` tag on every
  object the puller stores, so it is gated by the intel filter like any other
  community intel, and appears as its own badge in the UI.
- **`base_url`** is the remote TAXII **API root** (e.g. `https://host/taxii2/`);
  the puller requests `{base_url}collections/{collection}/objects/?since=…`.
- **Delta pulls** — each puller remembers its last sync timestamp in the
  `puller_state` table and sends it as `?since=`, so restarts resume from where
  they left off instead of re-pulling everything.
- **`enabled: false`** still lets you fire a one-shot **Pull now** from the UI
  (or `POST /community/pull/<name>`) — handy for testing a new source before
  committing it to background polling.

All pulled objects land in the feed tagged with the puller's `name`, then pass
through the [intel filter](#intel-filter-filtering-between-server-and-vision-one)
before reaching Vision One. **No community source pulls anything until you
enable it** — the server ships with all pullers off.

### 3. CSV import (GT-team ad-hoc intel)

For one-off intel uploads that don't fit the other paths. Upload a `.csv` in
the **Import CSV (GT team)** dashboard panel (or `POST /feed/import-csv`),
with **any** headers — they are fuzzy-mapped, then each value is validated
and typed:

| Header contains (case-insensitive) | Mapped to |
|------------------------------------|-----------|
| `ip_address`, `src_ip`, `dst_ip`, `destination`, `ip` | `ipv4-addr` (only if a valid IPv4) |
| `domain`, `hostname`, `host`, `fqdn` | `domain-name` (only if domain-shaped) |
| `md5`, `sha1`, `sha256`, `sha512`, `hash` | `file-hash` (hex, algo from length) |
| `indicator`, `value`, `ioc` (free text) | `indicator` |
| `label` / `tags` | labels (comma-separated) |
| `confidence` / `conf` | confidence (0–100, default 50) |

A row may carry **several** recognized values (e.g. both `src_ip` and a
domain) — each valid value becomes its own object. Rows with no
recognizable value are reported in `skipped`. Import uses **merge** mode
tagged `source='manual'`, so it **appends** to your manual feed and never
wipes existing rows (unlike the "Save feed (replace)" button).

```bash
# Raw CSV body (also accepts a multipart "file" field from the UI)
curl -X POST http://localhost:5000/feed/import-csv \
  -u admin:admin -H 'Content-Type: text/csv' \
  -d 'IP_Address,Destination,labels
1.2.3.4,evil.example.com,c2
5.6.7.8,bot.evil.net,apt'
# -> {"imported": 4, "skipped": [], "skipped_total": 0}
```

## Intel Filter (filtering between server and Vision One)

A read-time **gate** sits in front of the `/taxii2/` collection Vision One
polls. Its job is to **reduce false positives** and give you control over
which community intel actually reaches Vision One:

```
AlienVault OTX ──pull──▶ this server ──[intel filter]──▶ Vision One
```

Key properties:

- **Community data only.** Which sources are "community" is set by
  `intel_filter.community_sources`:
  - `[]` (default) → gate **every non-manual source** (the OTX puller and all
    `taxii_pullers:` entries), whatever they're named.
  - `['otx', 'otx-taxii', …]` → gate **only** those named sources.
  Your manually-fed intel (web UI / `POST /feed/ingest`, `source='manual'`)
  **always passes**, no matter what.
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
  community_sources: []          # default: gate ALL non-manual sources
  # community_sources: ['otx']   # or gate only these named sources
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
authentication (TAXII creds **and** the UI session cookie), subscription
management, STIX 2.1 object mapping (IP / domain / file-hash / indicator
patterns), TAXII bundle generation (including `match[type]`, `match[id]`,
and `added_after` query filters), the OTX poller (init, URL/headers,
indicator mapping, and manual-vs-OTX source isolation), the generic
**third-party TAXII 2.1 puller** (init, headers, fetch-and-merge, state
persistence, misconfigured handling), the **community source endpoints**
(`GET /community/pullers`, `POST /community/pull/<name>`), the **UI
login/logout/session** flow (cookie set, wrong-password 401, session grants
data access), the **intel gate** (private-IP drop, freshness, confidence
floor, blocklist, and that manual intel is never gated), **manual
revocation** (`POST /objects/<id>/revoke`, stickiness across saves,
`revoked: true` in the TAXII bundle) and **TTL auto-revocation** (per-type
aging sweep), and **CSV import** (fuzzy header mapping, merge-not-replace,
auth, bad-input handling).

## Security Considerations

- Use **HTTPS/TLS** for production deployments (configurable via reverse proxy).
- **Set a strong `ui.auth` password** and change it from the default
  `admin`/`admin` — anyone who knows it can manage the feed and trigger pulls.
- **Set `FLASK_SECRET`** (via `security.secret_key` / env) — the UI session
  cookie is signed with it; an unset/dev value lets a forged cookie
  authenticate to the data endpoints.
- Use strong, unique passwords and store them hashed.
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
- The object may be **revoked** (TTL auto-revocation or a manual revoke).
  `GET /objects` shows a `revoked` badge; the TAXII bundle serves it with
  `revoked: true` so Vision One drops it. Unrevoke to reinstate.
- The web UI still shows the object (the gate only affects the `/taxii2/`
  feed), so you can confirm it's *stored* but *withheld*. Loosen the relevant
  toggle (or add nothing / remove a blocklist entry), restart, and it's
  served again — nothing was deleted.

## Future Work (deferred — not implemented)

Assessed against a "modern TAXII server" feature list; deferred deliberately
because they are either off-mission for this single-consumer feed (Vision One)
or conflict with the offline / low-attack-surface design. Recorded here so
they are explicit, not forgotten:

- **Excel (.xlsx) import** — CSV is supported; .xlsx would add `openpyxl`
  (still offline-installable). Do only if the GT team actually ships .xlsx.
- **Non-TAXII HTTP feed connectors** — Abuse.ch / ThreatFox style pullers
  (OTX and *any* TAXII 2.1 server are already covered by the generic puller;
  MISP in particular can be added today as a `taxii_pullers:` entry).
- **Web scraping** (blogs / GitHub / paste sites, e.g. Playwright) — off-mission
  for a curated feed; ToS/legal risk; high noise floor.
- **LLM / NLP extraction** of unstructured text or PDFs into STIX — heavy
  dependency, contradicts the offline, low-attack-surface direction.
- **Auto-enrichment** (VirusTotal / WHOIS) — needs external APIs + keys and
  network egress; revisit only if Vision One consumers want enriched context.
- **AI/ML scoring & quarantine** — the rule-based intel gate already covers
  false-positive reduction in an auditable, offline way; an ML layer is a
  large scope addition with little to gain at this scale.
- **STIX relationships / threat actors / malware objects** — the store is flat
  IOCs; a full STIX 2.1 graph (relationships, `malware`, `threat-actor`) is a
  model-level change.
- **Collection-based RBAC** (multiple collections, per-client subscriptions)
  — single collection + single credential set fits one consumer; add when a
  second SIEM / firewall needs a different view.
- **`limit` / `offset` pagination** on Get Objects — objects are small; add
  only if a bundle ever grows too large.

## License

MIT License
