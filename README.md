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
│  │  /objects  /feed/ingest  │   │  - Subscription, PullerState     │  │
│  │  /community/pullers|pull │   │  - ApiKey, UIUser                │  │
│  │  /taxii2/  (gate applied)│   │    (scoped keys + logins)        │  │
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
2. **Web UI dashboard** — Single self-contained `intel-ui.html` behind a login (`ui.auth`). Organized into five tabs: **Feed** (the current feed with per-row **source** and **gate** badges, a **collection** selector when multiple collections exist, **search / type & status filters / pagination**, a withheld-by-filter panel, a **known-legitimate filter** panel with a one-click **Exclude** on served rows, and manual entry/publish), **Intel graph** (a dashboard of the fed intel — KPI tiles plus bar charts for **by category** (IP / domain / file hash / …), **by source**, **confidence distribution**, **pulled-over-time**, **withheld-by-filter**, and **top labels** (donut, share of label occurrences); scope switch Community / Manual / All), **Community sources** (puller status + "Pull now", with the same **search + pagination**), and **Import CSV / Excel** (GT-team ad-hoc import: `.csv` or `.xlsx`), and **API keys** (generate/revoke collection-scoped TAXII credentials). Serves all intel (the gate only affects what Vision One gets).
3. **STIX 2.1 Store** — Stores threat intelligence objects (IPs, file hashes, domains, URLs, emails, indicators, malware / threat-actor / campaign SDOs, and STIX *relationships* — a real graph, not just flat IOCs) in SQLite (or PostgreSQL). The database is the source of truth for what is served: TAXII polls read the stored rows directly (with a composite index on `(modified, stix_id)` for keyset pagination), and an in-memory copy is kept as a dashboard/coordination cache. Every object carries a `source` tag (`manual` | `otx` | a `taxii_pullers` name) and a `collection_id` (see [Multiple collections](#multiple-collections--per-client-rbac)) so manual and community intel coexist cleanly. Puller sync state (`last_sync`, `last_added`) is persisted in a `puller_state` table so delta pulls survive restarts. Dashboard mutations and logins are persisted in an `audit_events` table (see [Audit log](#audit-log)). The known-legitimate filter is persisted in a `benign_values` table (see [The known-legitimate filter](#the-known-legitimate-filter-keeping-legit-values-out-of-the-feed)).
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
| PyJWT 2.15.1 | SSO — verify the Microsoft ID-token JWT (only used when `sso.enabled`) |
| cryptography 50.0.2 | SSO — RSA key handling for ID-token signature verification |
| psycopg2-binary *(optional)* | PostgreSQL driver — only if you use a Postgres `database.url` |

> SQLite (the default) needs no driver. Install `psycopg2-binary` only when you
> switch `database.url` to PostgreSQL.

### Choosing the database

| | SQLite (default) | PostgreSQL (recommended) |
|---|---|---|
| Setup | None | `createdb taxii_feed` |
| Concurrent read + write | Single writer (file lock) | MVCC — readers never block the writer |
| Best for | Dev / single small feed | **Production** |

> **Schema & production setup** (tables, DDL, DBA-managed provisioning,
> privileges): see [Database Schema & Production Setup](IMPLEMENTATION_GUIDE.md#database-schema--production-setup)
> in the implementation guide. The tables are created automatically on first
> start — no manual DDL needed.

**Recommendation: PostgreSQL.** This server is read-heavy while being written —
Vision One polls the collection (full reads) at the same time the SOL poller /
your ingests write. Postgres MVCC handles that cleanly, its indexed
`modified` range scan keeps `?since=` delta polling fast at scale, and it has
the strongest JSON support (`JSONB`) if you later want to store raw STIX
objects and query them.

**MariaDB/MySQL is not supported.** The models declare unbounded `VARCHAR`,
which SQLite and PostgreSQL accept but MySQL rejects (`VARCHAR requires a length
on dialect mysql`), so `init_db()` cannot create the schema there. Adding it
would mean giving every string column an explicit length.

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
  # PostgreSQL (recommended) — see the `database:` block in
  # config.yaml for the exact URL format + driver to pip install.
  url: sqlite:///taxii_feed.db

security:
  secret_key: ${FLASK_SECRET}

taxii:
  # The collections this server serves. The AGGREGATE must come first: the
  # first entry is the primary collection, i.e. what Vision One polls.
  collections:
    - id: threat_intel                    # union of the two below
      members: [gt_intel, comm_intel]
      auth:                               # what Vision One is configured with
        username: 'your-taxii-username'
        password: 'your-taxii-password'
    - id: gt_intel                        # manual entry + CSV/Excel imports
    - id: comm_intel                      # OTX + third-party TAXII pullers

# Web UI dashboard login (SEPARATE from the TAXII credentials above)
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
  #   base_url: https://otx.alienvault.com/taxii/root   # OTX TAXII 2.1 API root
  #   username: 'your-otx-api-key'                       # OTX: API key = username
  #   password: ''
  #   collection: '<collection-uuid>'
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

`python server.py` serves through **waitress** (a production WSGI server), not
the Flask/Werkzeug development server. waitress is single-process and
multi-threaded on purpose: the OTX/TAXII pollers and the TTL sweeper are
in-process threads that must run exactly once, so N gunicorn *workers* would
each start their own. Tune it with `server.threads`; set `server.engine:
flask` (or `server.debug: true`) for the dev server during local work.

### Run with Docker (app + PostgreSQL + optional Cloudflare Tunnel)

A `Dockerfile` and `docker-compose.yml` are included: the app, a PostgreSQL
service, and an optional `cloudflared` tunnel. Secrets are **not** baked into
the image (`.dockerignore` excludes `.env`); the app container runs
unprivileged, PostgreSQL is not published to the host, and both services have
healthchecks.

```bash
# 1. Provide config/secrets in .env (see .env.example):
#    FLASK_SECRET, TAXII_AUTH_USER/PASSWORD, UI_AUTH_USER/PASSWORD,
#    POSTGRES_USER/PASSWORD/DB, and (for the tunnel) CLOUDFLARE_TUNNEL_TOKEN.
# 2. Build + start the app and database:
docker compose up -d --build

# App:  http://127.0.0.1:5000/ (loopback only; TAXII at /taxii2/)
```

Compose injects only the variables the app needs (the DB URL is built from
`POSTGRES_*` and pointed at the `postgres` service) — the tunnel token is
never passed to the app container.

**Cloudflare Tunnel (optional).** The `cloudflared` service is behind the
`tunnel` profile so the stack runs before the token exists:

```bash
CLOUDFLARE_TUNNEL_TOKEN=<token>   # in .env (Zero Trust → Networks → Tunnels
                                  # → your tunnel → the value after --token)
docker compose --profile tunnel up -d
```

With a **token-based (remotely managed)** tunnel the ingress rules live in the
Cloudflare Zero Trust dashboard, not in a local config: add a **Public
hostname** whose service/origin is `http://taxii:5000`. If the token is empty,
the connector exits on start (see `docker compose logs cloudflared`) — the app
and database are unaffected either way.

Adding the tunnel to an already-running stack is enough — Compose starts only
the missing service:

```bash
docker compose --profile tunnel up -d   # adds cloudflared alongside app + db
```

```bash
docker compose logs -f cloudflared     # connector health
docker compose down                    # stop (keeps the pgdata volume)
docker compose down -v                 # stop and delete the database volume
```

> The image installs `psycopg2-binary` so it can talk to the bundled
> PostgreSQL; the app is still a single process (`python server.py`) so the
> background pollers and TTL sweeper run as designed.

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

Once logged in, the **TAXII Feed Manager** dashboard opens on the **Feed** tab.
Use the top tabs to switch between **Feed**, **Intel graph**, **Community
sources**, **Import CSV / Excel**, and **API keys** (each is a deep link — the
URL hash updates, so `#graph` / `#sources` / `#import` / `#keys` open that tab
directly). On the
**Feed** tab you can:

1. **Current feed** — an editable table of everything in the feed. Each row
   shows a **source badge** (`manual` / `otx` / a puller name), a **gate
   badge** (`served` = passes the intel filter and is offered in the feed,
   `withheld` = filtered out, with the reason on hover), and a
   **Status** cell (`active` / `revoked`) with a **Revoke / Unrevoke** button
   for marking false positives.
   - **Search** — filters rows by value, label, type, or ID as you type.
   - **Type / Status filters** — narrow to one type and/or active/revoked.
   - **Pagination** — 15 rows per page (first/prev/next/last) so a large
     feed never runs the page down.
   - **Select** — tick the checkbox(es) of the rows to drop; the header
     checkbox selects/deselects every *matching* row (all pages), and the
     "N selected" counter tracks the selection.
   All of this is **client-side**: the full feed loads once and is filtered +
   paged in the browser (no server round-trips, works offline). Edits and
   deletes write back to the in-memory model, so nothing is lost across page
   turns. **Save reads the whole feed, not the visible page**, so filtering or
   paging can never silently drop rows on save. "Select all" acts on every
   *matching* row (all pages), not just the current one.
2. **Add new entry** — pick a type (IPv4 / domain / file hash / indicator),
   type the value. IDs and hash algorithms (MD5/SHA-1/SHA-256) are
   auto-derived, and values are validated. **Label** and **confidence
   (1–100)** are required for every entry — a row missing either is skipped
   (with a warning) rather than saved. New rows are added on the last page
   (and that page is shown) so they're never off-screen. Committing one field
   (blur) no longer rebuilds the table, so moving value → label → confidence
   never loses what you've typed.
3. **Save changes** — a true **save** (merge): keeps everything already in the
   feed and only **adds new rows + applies your edits** (value, type, labels,
   confidence). It never wipes, and checkboxes do **not** affect what is saved
   (they only drive *Purge selected*). Empty/invalid rows are skipped with a
   warning instead of being written or blocking the rest. On success the
   status line shows the result ("Saved N object(s)… including K new") and
   the view jumps to the page holding the newest entry and briefly highlights
   it, so you can see exactly what landed.
4. **Purge selected** — deletes the entries you **tick** (across the whole
   feed, not just the visible page). Rows start unselected; select a few,
   click it, and only those are dropped. The per-row **×** deletes a single
   entry.
5. **Purge all** — wipes the **entire** feed in one click (all sources, with
   a confirmation).
6. **Withheld by filter** — a panel listing every community object the
   [intel filter](#intel-filter-filtering-between-server-and-vision-one) is
   keeping out of Vision One, with the exact **reason** (Private / reserved
   IP, Stale, Low confidence, Blocklisted, or Known legitimate). These objects
   are still stored — nothing is deleted. A row withheld as *Known legitimate*
   is one you put on the filter below; **Remove** it there to serve it again.
7. **Known-legitimate filter** — add, list and remove the legitimate domains
   and IPs that must be **kept out of the Vision One feed**. A community object
   whose value matches an entry is **withheld**, so Vision One never sees it —
   serving a real domain would get legitimate traffic blocked. Enter a value and
   pick a match kind: **exact** (one value), **domain** (the domain and all
   subdomains) or **cidr** (an IP range). You can also click the one-click
   **Exclude** button on any served community row in the feed. The panel also
   shows the static `intel_filter.benign_values` / `benign_domains` /
   `benign_cidrs` rules from `config.yaml` (read-only here). See
   [The known-legitimate filter](#the-known-legitimate-filter-keeping-legit-values-out-of-the-feed).
8. **Community sources** — a table of the OTX puller plus each
   `taxii_pullers:` entry (kind, enabled/running, last sync, last added,
   status) with a **limit box** and a **Pull now** button. Type a number in
   the box to cap how many objects that one pull ingests (blank = the
   puller's configured cap). "Pull now" runs one fetch on demand
   (it works even while a puller is `enabled: false`, for a one-shot fetch),
   then refreshes the feed table. See
   [Community Sources](#community-sources-pulling-from-otx-or-any-taxii-21-server).
9. **Import CSV (GT team)** — upload a `.csv` with any headers (fuzzy-mapped
   to IPv4 / domain / file hash / indicator); appends to the manual feed. See
   [CSV import](#3-csv-import-gt-team-ad-hoc-intel).

> Items **8 (Community sources)** and **9 (Import CSV)** live on their own
> tabs, not the Feed tab. The **Community sources** tab has the same
> client-side **search** (name / kind / collection) and **pagination** as the
> feed table, so a long list of pullers stays navigable.

The UI is a single self-contained `intel-ui.html` (no CDN/JS dependencies,
works offline), served directly by the Flask app. The browser talks to the
server over same-origin requests carrying the session cookie. Destructive
actions (*Purge selected*, *Purge all*) confirm through a custom,
theme-matched modal (Esc / backdrop / Cancel = abort, Enter / button =
proceed) instead of the browser's native dialog.

## SSO — Microsoft Entra ID (Azure AD) sign-in

Optional, **OFF by default** (`sso.enabled: false`). When enabled, the login
page adds a **"Sign in with Microsoft"** button (OIDC **Authorization Code +
PKCE**) on top of the existing username/password login, which stays as a
fallback so the box is never locked out if the IdP is unreachable. A
successful SSO sign-in issues the **same** `taxii2_ui_session` cookie as a
local login, so everything downstream (dashboard, cookie-auth on the data
endpoints) is unchanged.

**Security model (two layers):**
1. **Primary** — assign the Entra app to a tenant **group** in the Azure
   portal (Enterprise application → Users and groups). Only assigned users can
   even reach the sign-in screen. This is the main control.
2. **Optional server-side allow-list** — `sso.allowed_domains`,
   `sso.allowed_upns`, `sso.allowed_groups` (defense-in-depth). Leave empty to
   rely on Entra assignment alone.

**Egress:** only `login.microsoftonline.com` is contacted — the *browser* for
the sign-in screen, and this *server* to exchange the code for a token and to
fetch/validate the signing keys (JWKS). The ID token is verified server-side
(RS256 signature, `iss`, `aud`, `exp`, and a per-login `nonce`), and the flow
uses a signed short-lived `state` cookie + PKCE to stop CSRF/replay.

**Setup:**
1. Azure portal → **App registrations → New registration** (single tenant).
2. **Authentication → Web** → add redirect URIs:
   - `http://localhost:5000/ui/sso/callback` (local HTTP testing — Microsoft
     allows `http://localhost` so you *can* test against the local server),
   - `https://<live-host>/ui/sso/callback` (production, HTTPS required).
3. **Certificates & secrets → New client secret** → copy the value.
4. **Overview** → note the Application (client) ID and Tenant ID.
5. **Users and groups** (the enterprise app) → add the group of allowed users.
6. In `config.yaml`, set `sso.enabled: true`, `tenant`, `client_id`, and
   `redirect_uri` (must exactly match one from step 2). Put the client
   secret in `.env` (see `.env.example`), then restart the server.

> Keep `client_secret` out of git — config.yaml references
> `${SSO_CLIENT_SECRET:-}`, which is filled from the `.env` file
> (git-ignored) or the process environment (which always wins).

### SSO endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /ui/sso` | Begin the OIDC flow — 302 to Microsoft's authorize URL with PKCE; sets a short-lived signed state cookie. `404` when disabled. |
| `GET /ui/sso/callback` | Microsoft redirects here (`?code=&state=`). Exchanges the code, validates the ID token, applies the allow-list, then 302 to `/` with the session cookie. `404` when disabled. |

`GET /ui/session` also returns `{..., "sso": {"enabled": bool, "provider": "Microsoft Entra ID"}}` so the UI shows the button only when SSO is on.

## Feeding Intel: API (curl)

### GET /feed

Returns the latest STIX feed in **TAXII 2 XML** format.

**Authentication:** the **data endpoints** are split by privilege —
**reads** (`/feed`, `/objects`, `/ui/stats`, `/ui/collections`,
`/ui/benign`, `/community/pullers`, `/taxii2/*`) accept the TAXII
credentials from
`taxii.auth` in `config.yaml` (sent as `X-Taxii-Username` /
`X-Taxii-Password` headers or HTTP Basic) **or** a valid UI session cookie
(from the dashboard login). **Writes** (`/feed/ingest`, `/feed/delete`,
`/feed/purge`, `/feed/import-csv`, `/objects/<id>/revoke`,
`/objects/<id>/exclude`, `/ui/benign`,
`/ui/benign/<id>/delete`,
`/community/pull/<name>`) need the **dashboard session, the UI credentials,
or an optional `taxii.admin_auth` principal** — TAXII credentials are
read-only on purpose, so the credential handed to Vision One cannot change
the feed. Unauthenticated requests get `401`. For curl reads, use the TAXII
credentials; for curl writes, use the UI credentials:

```bash
# read (consumer credential)
curl -u "$TAXII_AUTH_USER:$TAXII_AUTH_PASSWORD" http://localhost:5000/objects
# write (dashboard credential)
curl -u "$UI_AUTH_USER:$UI_AUTH_PASSWORD" -X POST http://localhost:5000/feed/ingest \
  -H 'Content-Type: application/json' -d '{"stix_objects": [...]}'
```


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

Accepts STIX 2.1 JSON objects into the feed. The `mode` field selects the
write semantics:

- **`"replace"`** (default, legacy) — wipes and rebuilds the *manual* feed
  of the **target collection** (community-sourced rows are untouched).
- **`"merge"`** — upsert by STIX id: edits/labels/confidence are refreshed,
  new ids are added, **everything else is preserved**. This is what the web
  UI **Save changes** button sends.

Optional `collection` field targets a TAXII collection (default: the primary
collection — see [Multiple Collections](#multiple-collections--per-client-rbac)).

**Supported STIX 2.1 types:** `ipv4-addr`, `domain-name`, `file-hash`,
`indicator`, `url`, `email-addr`, `ipv6-addr`, `mac-addr`,
`windows-registry-key`, `autonomous-system`, `malware`, `malware-family`,
`threat-actor`, `campaign`, `report`, `identity`, `attack-pattern`,
`vulnerability`, and `relationship` (a full STIX graph, not just flat IOCs).
Every object is validated before storage — id/type shape (`<type>--<value>`,
prefix must match the type), confidence 0–100, list-shaped labels, parseable
timestamps, complete relationship triples, and `object_refs` on reports.
Invalid objects are **skipped with a warning** (never block the batch) — the
response's `objects_count` reflects what was actually stored.

Objects are **served back as spec-valid STIX 2.1**: IOCs as `indicator`
objects (with a `pattern` + `valid_from` — the source's `valid_from` is kept
when the puller provides it), and SDO/SRO types as their own type with a
`<type>--<uuid>` id; a report's `object_refs` are passed through verbatim.

**Request Body:**
```json
{
  "mode": "merge",
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
  "mode": "merge",
  "objects_count": 3
}
```

### POST /feed/delete

Deletes the given STIX ids from the feed (**any source**). This is what the
web UI **Purge selected** button sends (the ids of the ticked rows).
Per-row removal is the × button; the full-feed wipe is `DELETE /feed/purge`.

**Request Body:**
```json
{ "ids": ["ipv4-addr--192-168-1-100", "domain-name--789"] }
```

**Response:**
```json
{ "deleted": 2, "ids": ["ipv4-addr--192-168-1-100", "domain-name--789"] }
```

`400` if `ids` is missing/empty; `401` without credentials.

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
| `GET /ui/session` | Current session: `{"authenticated": bool, "user": str\|null, "role": str\|null, "can_write": bool, "can_admin": bool}` |
| `GET /ui/collections` | Collection registry for the dashboard selector: `{"collections": [{id,title,members,aggregate}], "primary": id, "manual": id, "community": id}` — `manual`/`community` are where the dashboard routes a write, since an aggregate is read-only |
| `GET /ui/keys` | Issued API keys (prefix, label, collections, types, expiry, last used, enabled) — never the secret. Also returns the `collections` and `types` registries for the dashboard. Requires an **admin** principal |
| `POST /ui/keys` | Body `{"label", "collections": [id…], "types": [type…], "expires_days"?, "rate_limit"?, "rate_window"?, "max_objects"?}`. `types` is the required object-type allow-list. Returns the plaintext key **once** (`201`). Requires an **admin** principal |
| `POST /ui/keys/<id>/revoke` | Disable a key permanently (admin) |
| `GET /ui/users` | Dashboard users (username, role, enabled, created, last login) — never a password hash. Requires an **admin** principal |
| `POST /ui/users` | Body `{"username", "password", "role"}` (role: `viewer`\|`editor`\|`admin`). `409` on a duplicate, `400` on a bad role or a password under 12 chars. Returns `201` (admin) |
| `POST /ui/users/<id>` | Change a user's `role`, `enabled` or `password`. `400` if it would remove the last enabled admin (admin) |
| `POST /ui/users/<id>/delete` | Delete a user; their session stops working immediately (admin) |
| `GET /ui/audit` | Audit trail, newest first: `{"events": [{id,created,actor,role,via,ip,action,target,collection,count,detail}], "count", "limit", "max_limit", "truncated", "actions", "generated"}`. `?limit=` (default 200, cap 1000), `?action=` / `?actor=` exact-match filters. Requires an **admin** principal |
| `GET /ui/stats` | Aggregates for the **Intel graph** tab. `?scope=community\|manual\|all` (default community) and `?collection=<id>`: totals, `categories`, `by_source`, `withheld_reasons`, `confidence` (histogram), `timeline`, `top_labels`. |
| `POST /ui/login` | Body `{"username","password"}` checked against `ui.auth`. On success sets the http-only `taxii2_ui_session` cookie (signed with `security.secret_key`, lifetime `ui.session_ttl`); `401` on bad credentials. |
| `POST /ui/logout` | Deletes the session cookie. |

### Known-legitimate filter endpoints

The dynamic half of the known-legitimate filter (see
[The known-legitimate filter](#the-known-legitimate-filter-keeping-legit-values-out-of-the-feed)).
An entry names a legitimate value that the community gate **withholds**, so
Vision One never sees it. Reads need any authenticated principal; writes need a
**write** role (`editor`/`admin`) — TAXII credentials get `401`.

| Endpoint | Purpose |
|----------|---------|
| `GET /ui/benign` | `{"benign": [{id,value,kind,note,created,created_by}], "count", "kinds", "config": {benign_values,benign_domains,benign_cidrs}}`. `config` reflects the read-only `intel_filter:` rules from `config.yaml`. |
| `POST /ui/benign` | Body `{"value", "kind": "exact\|domain\|cidr", "note"?}`. Idempotent — an identical `(value, kind)` returns `200` with `changed:false` instead of creating a duplicate. `400` on a bad kind, empty value, malformed domain or invalid CIDR; `201` on create. |
| `POST /ui/benign/<id>/delete` | Remove an entry; the object is served again from the next poll. `404` if unknown. |

### Object lifecycle endpoints

| Endpoint | Purpose |
|----------|---------|
| `POST /objects/<stix_id>/revoke` | **Write** (dashboard session / UI credentials / `taxii.admin_auth`; TAXII credentials get `401`). Body `{"action":"revoke"}` (default) or `{"action":"unrevoke"}`. Sets/clears the STIX `revoked` flag. A revoked object stays stored and is served to Vision One with `revoked: true` so it can be purged. `404` if the id is unknown, `400` on a bad action. |
| `POST /objects/<stix_id>/exclude` | **Write** (as above). One-click known-legitimate filter: looks the object up, derives its value and records a benign entry, so the gate **withholds** it (Vision One never sees it). Optional body `{"kind": "exact\|domain\|cidr", "note"?}`; the default is `domain` for a domain object (exclude a whole domain) and `exact` otherwise. `404` if the id is unknown, `400` on a bad value/kind. |

### CSV import endpoint

| Endpoint | Purpose |
|----------|---------|
| `POST /feed/import-csv` | **Write** (dashboard session / UI credentials / `taxii.admin_auth`). GT-team ad-hoc intel. Multipart `file` field (UI) or raw CSV body; capped at `security.max_upload_bytes` (25 MB → `413`) and `security.max_import_rows` rows. Fuzzy header → type mapping, per-value validation, merge (append) as `source='manual'`. Returns `{imported, skipped[], skipped_total}`. `400` if nothing recognizable or the file can't be parsed (no driver internals echoed). See [CSV import](#3-csv-import-gt-team-ad-hoc-intel). |

### Community source endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /community/pullers` | Status of all community sources: the OTX puller plus each `taxii_pullers:` entry (`id`, `name`, `kind`, `enabled`, `running`, `limit`, `base_url`, `collection` for TAXII, `last_sync`, `last_added`, `last_status`, `last_message`). |
| `POST /community/pull/otx` | **Write** (dashboard session / UI credentials / `taxii.admin_auth`). Run one OTX pull cycle now (the UI "Pull now"). Optional `limit` (JSON `{"limit": N}` or `?limit=N`) caps objects this cycle. Returns `{name, added, error, last_sync, last_status, limit?}`. |
| `POST /community/pull/<name>` | **Write** (as above). Run one pull cycle now for a `taxii_pullers:` entry named `<name>`, with the same optional `limit`. `404` if unknown, `400` if misconfigured or the limit is not a positive integer. Works even when the puller is `enabled: false` (one-shot fetch). |

> **Limiting a pull.** "Pull now" accepts a per-cycle **limit** — the dashboard's
> Community-sources table has a **limit box** next to each Pull button (blank =
> the puller's configured cap: `otx.max_indicators_per_poll` /
> `taxii_pullers[].max_objects_per_poll`). The API takes `{"limit": N}` (or
> `?limit=N`). The value is a *maximum* — the pull may ingest fewer (duplicates
> are merged, and a source may have less).

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
  collections:
    - id: threat_intel                # the union Vision One polls (primary)
      members: [gt_intel, comm_intel]
      auth:
        username: 'admin'             # TAXII client username
        password: 'admin'             # TAXII client password
    - id: gt_intel                    # manual intel
    - id: comm_intel                  # pulled community intel
```

### Step 2: Feed intel

Add objects via the web UI (`http://<server>:5000/`) or `POST /feed/ingest`.
They are stored in `gt_intel` (the manual feed) and served — together with the
community feed — from the `threat_intel` union that Vision One polls.

### Step 3: Point Vision One at this server

In Vision One, create a TAXII 2.1 data source / feed subscription:

| Field | Value |
|-------|-------|
| **URL / Endpoint** | `http://<this-server>:5000/taxii2/` |
| **Protocol** | TAXII 2.1 |
| **Collection** | `threat_intel` |
| **Username** | `admin` (from the aggregate's `auth:`) |
| **Password** | `admin` (from the aggregate's `auth:`) |
| **Poll interval** | 15–30 minutes |
| **Object types** | IPv4, domain, file hash (indicator) |

The client does: discover `/taxii2/` → list `/taxii2/collections/` → poll
`/taxii2/collections/threat_intel/objects/`, receiving a STIX 2.1 JSON bundle
wrapped in a TAXII 2.1 message.

### TAXII 2.1 endpoints exposed

| Endpoint | Purpose |
|----------|---------|
| `GET /taxii2/` | API Root + Server Discovery |
| `GET /taxii2/collections/` | List collections — **only the collections the authenticated principal's credentials may read** (multi-collection RBAC; one collection = one credential set) |
| `GET /taxii2/collections/<id>/` | Collection info (`can_read`) — `404` unknown id, `401` with another collection's credentials |
| `GET /taxii2/collections/<id>/objects/` | **Poll STIX 2.1 objects** (supports `?since=`/`?added_after=`, `?match[type]=`, `?match[id]=` — comma-separated lists allowed — and `?limit=` + `?next=` pagination). With an API key, the result is additionally narrowed to the key's `types` allow-list and capped by its `max_objects`. |
| `POST /taxii2/collections/<id>/objects/` | Add-objects ack (read-only feed → no-op) |
| `GET /taxii2/status/<id>/` | Status (reports `complete`) |
| `GET /taxii2/subscriptions/` | Subscription list (empty) |

Auth is **HTTP Basic** (the TAXII standard) — the same `taxii.auth`
credentials. `?since=<ISO8601>` (alias `?added_after=`) returns only objects
modified after that timestamp, enabling efficient delta polling. Standard
TAXII 2.1 filtering is also supported:

```bash
# only domains
curl -u admin:admin 'http://localhost:5000/taxii2/collections/threat_intel/objects/?match[type]=domain-name'
# only specific objects
curl -u admin:admin 'http://localhost:5000/taxii2/collections/threat_intel/objects/?match[id]=domain-name--evil-example-com'
```

**Pagination (TAXII 2.1 §5.3):** `?limit=N` caps a page and the response
carries `more` + a `next` cursor (keyset-based on `(modified, stix_id)`, so
pages stay consistent while the feed changes and never loop):

```bash
curl -u admin:admin 'http://localhost:5000/taxii2/collections/threat_intel/objects/?limit=100'
# -> {..., "more": true, "next": "<opaque-cursor>", ...}
curl -u admin:admin 'http://localhost:5000/taxii2/collections/threat_intel/objects/?limit=100&next=<opaque-cursor>'
```

Malformed `limit`/`since`/`next` values return a TAXII `400` (error code
`malformed`) instead of being silently ignored.

A request that omits `?limit=` is still capped at `taxii.max_objects`
(10 000) and carries `more`/`next` like any other page, so one poll can never
materialise an entire collection. Follow `next` until `more` is false.

**Timestamps.** Served objects carry the **stored** `created`/`modified`, not
the time of the request. `created` never changes for an object; `modified`
advances only when the object actually changes (a merge refresh, a revoke).
This is what makes `?added_after=` delta sync work — a client can record the
newest `modified` it has seen and use it as its resume point, and the same
object is not re-reported as "just modified" on every poll.

> **Revoked objects** are included in the bundle with `revoked: true` (see
> [Indicator Lifecycle](#indicator-lifecycle-ttl--revocation)) so clients can
> purge them — they are never silently omitted.

### Verifying it works (without Vision One)

Trend Micro Vision One / XDR are **TAXII 2.1 clients**, so the authoritative
stand-in is the OASIS reference client, `taxii2-client`.

> **Not Cabby.** [Cabby](https://cabby.readthedocs.io) is a **TAXII 1.0/1.1**
> client ("supports all TAXII services according to TAXII specification
> (v1.0 and v1.1)"); it cannot talk to a TAXII 2.1 server and will fail at
> discovery. Use `taxii2-client` (below) for 2.1.

```bash
# 1. Discover the API root
curl -u admin:admin http://localhost:5000/taxii2/

# 2. Poll objects (raw TAXII 2.1 message envelope)
curl -u admin:admin http://localhost:5000/taxii2/collections/threat_intel/objects/

# 3. One-liner with the official OASIS reference client (recommended)
pip install taxii2-client
python -c "from taxii2client import ApiRoot; r=ApiRoot('http://localhost:5000/taxii2/',user='admin',password='admin'); r.refresh_collections(); print(r.collections[0].get_objects())"
```

**Repeatable check** (discovery, Get Objects, the spec filters — including
*comma-separated* `match[type]`/`match[id]` — pagination, and per-collection
RBAC). Exits non-zero on any failure, so it can gate a deploy:

```bash
pip install taxii2-client requests
TAXII_URL=http://localhost:5000/taxii2/ TAXII_USER=admin TAXII_PASSWORD=admin \
  TAXII_COLLECTION=threat_intel \
  TAXII_PREMIUM_USER=<2nd-collection-user> TAXII_PREMIUM_PASSWORD=<2nd-collection-pass> \
  python tests/verify_reference_client.py
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

> **Note on ingest modes.** `POST /feed/ingest` takes an optional `mode`:
> *replace* (default — wipes and rebuilds the `source='manual'` feed of the
> **target collection**) or *merge* (upsert by STIX id, append-only). The
> web UI **Save changes** button uses *merge*, so a save never wipes
> anything (manual **or** community intel); dropping entries is an explicit
> action (*Purge selected* / × / *Purge all*). The OTX and TAXII pullers
> also use *merge* mode. This keeps hand-fed intel and pulled community
> intel independent of each other.

## Collections: segregation, the aggregate, and scoped API keys

The feed is split by **provenance**, and consumers get exactly the slice they
should have:

| Collection | Contents | Written by |
|---|---|---|
| `gt_intel` | hand-curated ground truth | web UI entry + CSV/XLSX import |
| `comm_intel` | pulled community intel | OTX + third-party TAXII pullers |
| `threat_intel` | **the union of the two** | nobody — it is an aggregate |

`threat_intel` is listed **first**, which makes it the primary collection: the
default target of the dashboard and of any TAXII read that names no
collection. That is what Vision One polls, so it keeps seeing everything.

An **aggregate** is a collection with a `members:` list. It serves the union of
its members' objects and owns no rows of its own, so it is **read-only**: a
write naming it is rejected with `400` telling you which members to use. Members
must be other *leaf* collections (a nested aggregate is dropped with a warning,
keeping the union a flat one-level fact), and an aggregate left with no valid
member is a **startup error** — a silently empty feed is the one failure that
looks like "no intel yet". `GET /taxii2/collections/<id>/` advertises the union
in `meta.members`.

```yaml
taxii:
  collections:
    - id: threat_intel               # primary: the union Vision One polls
      members: [gt_intel, comm_intel]
      auth:
        username: '${TAXII_AUTH_USER}'
        password: '${TAXII_AUTH_PASSWORD}'
    - id: gt_intel                   # manual intel
    - id: comm_intel                 # pulled community intel
```

**How RBAC works:**

- **One credential set per collection.** A TAXII client authenticates with
  the collection's own HTTP Basic credentials (or `X-Taxii-*` headers).
- **Collection listing is scoped.** `GET /taxii2/collections/` returns only
  the collections the authenticated principal may read. Holding the
  *aggregate's* credentials does **not** grant a direct read of a member:
  the union is one collection, its members are others. Get Objects for a
  collection the credentials can't read returns `401`.
- **Objects are stored per collection.** Every object carries a
  `collection_id`; the data endpoints take an optional `collection` field /
  `?collection=` (web UI: the **Collection** selector on the Feed tab;
  default = the primary collection). `POST /feed/ingest {"collection":
  "gt_intel", ...}` targets a specific collection and `GET
  /objects?collection=gt_intel` views it. "Purge all" on the union clears
  the **union of its members** (not everything): a bare `DELETE /feed/purge`
  with no `?collection=` still wipes every collection, for scripts.
- **Writes are operator-only.** Every item above is a *write*: it needs the
  dashboard session, the UI credentials or `taxii.admin_auth`. A collection's
  TAXII credentials can list and read that collection and nothing else.
- **Where the pollers write** is per-puller config: `otx.ingest_collection`
  and each `taxii_pullers[].ingest_collection`, defaulting to `comm_intel`.
  It is *not* the puller's `collection` key — on a TAXII puller that one
  names the **upstream** collection being read. Pointing `ingest_collection`
  at an aggregate is ignored with a warning, so community data can never be
  filed under the union.

### API keys (scoped consumer credentials)

Instead of a second static password per consumer, generate one in the
dashboard's **API keys** tab. A key is scoped to one or more collections and to
a set of object types, can expire, and can carry its own rate limit.

- **Format** `taxii_<prefix>_<secret>`, used exactly like a password: the
  **prefix** as the username and the key as the password
  (`curl -u <prefix>:<key>`). Vision One speaks HTTP Basic, so paste them
  into its username/password fields; the `X-Taxii-Username` /
  `X-Taxii-Password` headers work too.
- **Stored hashed.** Only the cleartext prefix (indexed, for O(1) lookup and
  for the listing) and a SHA-256 of the secret are persisted. A fast hash is
  deliberate: the secret is high-entropy random, so there is nothing to
  brute-force, and this runs on every poll. The plaintext is shown **once**,
  at creation, and is never logged (log lines carry the prefix only).
- **Read-only.** A key authenticates reads; every write still needs the
  dashboard session, the UI credentials or `taxii.admin_auth`.
- **Rate limiting.** An optional sliding window per key returns `429` with
  `Retry-After` once exceeded. It is in-memory and per-process — the same
  caveat as the auth-failure throttle: it resets on restart, and scaling to
  multiple workers would need a shared store (Redis). The server is
  deliberately single-process (waitress), so one table is the whole picture.
- **Per-response IOC ceiling (`max_objects`).** For consumers with a
  *per-poll ingest limit* (an XDR that chokes if handed 15 000 objects at
  once), a key can cap how many objects one response carries. The effective
  page is `min(client limit, key max_objects, taxii.max_objects)`, so a
  client asking for more than its key allows still gets the cap, with
  `more: true`. Blank/`0` inherits the server-wide cap.

  > **This throttles delivery, not entitlement — and it needs the client's
  > cooperation.** It does not change *which* objects the key may see, only
  > how many arrive per page. Because pages are ordered oldest-first
  > (`modified, stix_id`), a client that ignores `more`/`next` **and** polls
  > without `added_after` will receive the same first page forever and never
  > reach the rest of the feed. A capped page is therefore logged:
  >
  > ```
  > API key <prefix> served a capped page (max_objects=500, 500 object(s),
  > more remain); request used the next cursor
  > ```
  >
  > `used the next cursor` (or `added_after`) means the client is paginating
  > correctly. `no cursor and no added_after` repeated across polls means it
  > is not, and the cap is starving it — raise the cap, or fix the client's
  > polling. The correct client pattern is
  > `?limit=500&added_after=<modified of the newest object received>`.
- **Object-type allow-list (`types`).** A key must be scoped to the object
  **types** it may be served — a strict allow-list. Any type not selected is
  withheld from that key's Get Objects responses (unlike `max_objects`, this
  changes *which* objects the key may see). Every stored type is selectable, so
  the list covers both the IOC kinds (`ipv4-addr`, `domain-name`, `file-hash`,
  `url`, `email-addr`, `ipv6-addr`, …) and the STIX context objects (`report`,
  `relationship`, `malware`, `threat-actor`, …). Selecting `indicator` means
  *all* IOC values (they are all served as STIX `indicator`s) — it does not
  unlock non-IOC objects. The scope is applied in addition to the client's
  `match[type]`, so a client can narrow further but never widen past its key.
  A key's `types` is required at creation (at least one); existing keys were
  backfilled with the full list, so their behaviour is unchanged.

  > **Boundary note.** The type scope is enforced on the `/taxii2/` Get Objects
  > surface (where a consumer key polls). The dashboard's `/objects` and
  > `/feed` endpoints are read with a UI session or other credentials and are
  > not scoped by a key's `types` — exactly as they are not scoped by its
  > `collections` today.
- **Revocation** is permanent: `POST /ui/keys/<id>/revoke` disables the key,
  and it starts failing authentication immediately.

### Dashboard users (multi-user with roles)

The dashboard is no longer a single shared login. The **Users** tab (admins
only) creates logins, each with a role:

| Role | Can do |
|------|--------|
| `viewer` | read everything in the dashboard (feed, graph, sources, stats) |
| `editor` | viewer **+** data mutations: ingest, CSV/Excel import, delete, revoke, purge, community pulls |
| `admin` | editor **+** API-key and user management |

- **Enforced server-side, on every request.** The role is re-resolved from the
  `ui_users` table per request rather than baked into the session cookie, so
  disabling a user, changing their role, or deleting them takes effect on their
  **next request** — no re-login, and no waiting for the cookie to expire. The
  dashboard hides controls a role cannot use, but that is only cosmetic; the
  server is the boundary.
- **Passwords** are hashed with werkzeug (scrypt/pbkdf2). That runs once per
  *login*, not per request, so an adaptive hash is correct here — unlike API
  keys, which are verified on every poll and therefore use a fast SHA-256.
- **`ui.auth` is kept as a break-glass admin.** The static pair is deliberately
  *not* stored in `ui_users`, so it cannot be locked out by a bad role edit and
  still works exactly as before. It is always an admin.
- **SSO users** have no local row (their identity lives in the IdP), so they
  take `sso.default_role` — `viewer` by default. Being authenticated by the
  tenant should not by itself grant write access to the feed.
- **You cannot lock yourself out.** The last enabled admin cannot be demoted,
  disabled or deleted (`400`); create a second admin first.
- **Audit lines name the actor.** Mutations log
  `… by alice (editor via session) from 203.0.113.9`, so a shared login is no
  longer indistinguishable — you can tell *who* purged the feed, not just from
  which IP. See [Audit log](#audit-log) for the durable, queryable trail.

> First run: log in with `ui.auth`, open **Users**, and create yourself a real
> admin account before sharing the dashboard. Leave `ui.auth` set as the
> break-glass credential.

### Audit log

Every successful dashboard mutation and every successful login is also
appended to an `audit_events` table, readable in-app at `GET /ui/audit` (or the
**Audit log** tab, admins only). It answers "who changed what, from where"
without grepping the server log — and the rows outlive a restart.

**Recorded actions:** `feed.ingest`, `feed.import`, `feed.delete`,
`feed.purge`, `object.revoke`, `object.unrevoke`, `community.pull`,
`key.create`, `key.revoke`, `user.create`, `user.update`, `user.delete`,
`benign.create`, `benign.delete` and `auth.login`. Failed logins and
failed (4xx/5xx) requests are **not** recorded, and secrets never are: a
`key.create` row stores the key **prefix**, never the plaintext.

Each row carries `created`, `actor` (username, or `anonymous`), `role`, `via`
(`session` \| `ui_auth` \| `sso` \| `admin_auth`), `ip`, `action`, `target`
(e.g. a STIX id, username or key prefix), `collection`, `count` and a
human-readable `detail`.

```bash
curl -u "$UI_AUTH_USER:$UI_AUTH_PASSWORD" \
  'http://localhost:5000/ui/audit?limit=100&action=feed.purge&actor=alice'
```

`GET /ui/audit` returns a **bounded newest-first window** — `?limit=` (default
200, hard cap 1000), plus optional exact-match `?action=` / `?actor=`. The tab
searches and pages the window client-side. A malformed `limit` is a `400`; an
unknown `action`/`actor` is simply an empty result.

**Retention is destructive and configurable** (`audit:` in `config.yaml`):
`retention_days` (default 90) drops older rows and `max_events` (default
100000) trims the oldest beyond the cap. Set either to `0`/`null` to disable
that bound — `0`/`0` keeps every row forever, and then no pruner thread starts.
Audit writes are best-effort: a failure is logged and swallowed, so it can
never fail the request it is recording.

**Upgrading from the pre-segregation single collection.** The old rows lived
under `collection_id='threat-intel'`, which no longer names anything. On the
first boot with a `members:` aggregate configured, they are re-homed once —
`source='manual'` (or unknown) to `gt_intel`, everything else to
`comm_intel` — before the server starts serving, so there is no empty-feed
window. The migration is idempotent and does nothing when the legacy id is
still a configured collection. Note that the old id is **gone**: a client
configured with `/taxii2/collections/threat-intel/objects/` must be pointed
at `threat_intel`.

See the `collections:` block in `config.yaml` and the `TAXII_AUTH_USER` /
`TAXII_AUTH_PASSWORD` keys in `.env.example`.

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
    base_url: https://otx.alienvault.com/taxii/root   # OTX TAXII 2.1 API root
    username: 'your-otx-api-key' # OTX uses the API key as the username
    password: ''
    collection: '<collection-uuid>'   # from GET /taxii/root/collections/
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

For one-off intel uploads that don't fit the other paths. Upload a `.csv`
**or `.xlsx`** in the **Import CSV / Excel (GT team)** dashboard panel (or
`POST /feed/import-csv`, multipart `file` field — the first row is the
header), with **any** headers — they are fuzzy-mapped, then each value is
validated and typed:

| Header contains (case-insensitive) | Mapped to |
|------------------------------------|-----------|
| `ip_address`, `src_ip`, `dst_ip`, `destination`, `ip` | `ipv4-addr` (valid IPv4) **or** `ipv6-addr` (valid IPv6) |
| `domain`, `hostname`, `host`, `fqdn` | `domain-name` (only if domain-shaped) |
| `md5`, `sha1`, `sha256`, `sha512`, `hash` | `file-hash` (hex, algo from length) |
| `indicator`, `value`, `ioc` (free text) | `url` / `email-addr` / `ipv6-addr` / `mac-addr` / `autonomous-system` (value-shaped) or `indicator` (other text) |
| `label` / `tags` | labels (comma-separated) |
| `confidence` / `conf` | confidence (0–100, default 50) |

A row may carry **several** recognized values (e.g. both `src_ip` and a
domain) — each valid value becomes its own object. Rows with no
recognizable value are reported in `skipped`. Import uses **merge** mode
tagged `source='manual'`, so it **appends** to your manual feed and never
wipes existing rows (unlike the "Save feed (replace)" button). Pass a
`collection` form field to import into a specific TAXII collection instead
of the primary (the UI sends the collection selected on the Feed tab).

```bash
# Raw CSV body (also accepts a multipart "file" field from the UI; .xlsx works too)
curl -X POST http://localhost:5000/feed/import-csv \
  -u "$UI_AUTH_USER:$UI_AUTH_PASSWORD" -H 'Content-Type: text/csv' \
  -d 'IP_Address,Destination,labels
1.2.3.4,evil.example.com,c2
5.6.7.8,bot.evil.net,apt'
# -> {"imported": 4, "skipped": [], "skipped_total": 0}
```

> `.xlsx` needs `openpyxl` (in `requirements.txt`) plus `defusedxml`, which
> openpyxl picks up automatically to parse an untrusted workbook with a
> hardened XML parser (no DTD entity expansion / "billion laughs"). The
> server boots without them and returns a clear error only on upload.

### Sanitization / injection behaviour of the upload field

The upload is parsed as **data only** — nothing in a `.csv`/`.xlsx` is ever
interpreted as code:

| Attack class | Why it does not work |
|---|---|
| SQL injection | Rows become Python dicts handed to SQLAlchemy; there is no string-built SQL anywhere (the only `text()` statements are the fixed-column migrations). A value like `1;DROP TABLE stix_objects;--` is stored verbatim as a value. |
| Command / code execution | The process has no `subprocess`, `os.system`, `eval`, `exec`, `pickle` or `yaml.load` path; the loader uses `yaml.safe_load` for config only. `$(id)` / backticks in a cell are literal text. |
| STIX-id / object forging | The id is **derived** from the value (slugged to `[A-Za-z0-9-]+`, or a `uuid5`), never taken from the file. A `stix_id`, `source`, `collection_id` or `revoked` column is not a recognized header and is ignored — imports are always `source='manual'` into the `collection` you pass as a form field (validated against the registry, `400` if unknown). |
| XSS | Values are returned as JSON and rendered by the dashboard with `textContent`/`xmlEsc`; escaping happens at the render boundary, so `<script>` in a cell is displayed as text. |
| Path traversal | The uploaded filename is used *only* to decide `.xlsx` vs CSV — the body is read into memory (`f.read()`); nothing is written to disk. |
| Formula injection (CSV/Excel "CSV injection") | **Latent, not exploitable today**: the server never writes feed values back into a CSV/XLSX (there is no export endpoint; the dashboard's "Download sample" is a static template). If an export is ever added, prefix values starting with `= + - @`, tab or CR with `'`. |
| Zip bomb / oversized body | `security.max_upload_bytes` (25 MB, enforced by Flask → `413`) and `security.max_import_rows` (50 000, with a truncation note) bound the work; `load_workbook(read_only=True, data_only=True)` streams rows and never evaluates formulas. |
| Error-text disclosure | A workbook that fails to parse returns `could not parse workbook` — the parser's own message stays in the server log. |

Each successful import is logged with the object count, target collection and
client IP (`Import via /feed/import-csv from …`).

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
- **Known-legitimate filter.** `intel_filter.benign_values` /
  `benign_domains` / `benign_cidrs` (config) and the `benign_values` table
  (dashboard, no restart) name legitimate values that are **withheld** — so
  Vision One never sees them and cannot block real traffic on them. See
  [The known-legitimate filter](#the-known-legitimate-filter-keeping-legit-values-out-of-the-feed).

### The filter rules (all config toggles in `intel_filter:`)

| Rule | Config key | Default | Withholds a community object when… |
|------|-----------|---------|------------------------------------|
| Known legitimate | `benign_values` / `benign_domains` / `benign_cidrs` | `[]` (off) | The value matches an entry (exact / domain+subdomains / CIDR). See [below](#the-known-legitimate-filter-keeping-legit-values-out-of-the-feed). |
| Private/reserved IPs | `drop_private_ips` | `true` | The IP is non-routable / special-use: `10/8`, `172.16/12`, `192.168/16`, `127/8`, `169.254/16`, `0/8`, `240/4`, IPv4-mapped v6, CGNAT, IANA reserved. These dominate OTX honeypot feeds. |
| Freshness window | `freshness_days` | `30` | `last_seen`/`modified` is older than N days (stale). Set `null` to disable. |
| Confidence floor | `min_confidence` | `null` (off) | Confidence is below the floor. OTX community objects default to `70`. |
| Value blocklist | `blocklist` | `[]` (off) | The exact value (IP / domain / hash / name, case-insensitive) is listed. |

A community object is withheld if it trips **any** active rule. When an
object is withheld, the server logs e.g. `Intel gate withheld N community
object(s) from the TAXII feed`.

### The known-legitimate filter (keeping legit values out of the feed)

The other rules are value-agnostic — they catch a *kind* of noise but cannot
know that a specific domain is legitimate. So a community feed will occasionally
flag a domain or IP that is real infrastructure (a login portal, a CDN, a cloud
range). Serving it would make Vision One **block** that legitimate traffic. The
**known-legitimate filter** names those values: a matching community object is
**withheld** from the feed, so Vision One never sees it.

It comes in two forms, and they combine:

| Static (config.yaml) | Dynamic (dashboard) | Matches |
|----------------------|---------------------|---------|
| `benign_values: []` | Add value, kind **exact** | One value — IP / domain / hash / name / URL, case-insensitive. |
| `benign_domains: []` | Add value, kind **domain** | The domain **and every subdomain**: `microsoft.com` covers `login.microsoftonline.com`. |
| `benign_cidrs: []` | Add value, kind **cidr** | An IP **network** — CIDR is supported. Use it for a whole cloud / Office 365 / CDN range. |

The **dynamic** half lives in the `benign_values` table and is managed from the
dashboard with **no config edit and no restart** — either the **Known-legitimate
filter** panel on the Feed tab, or the one-click **Exclude** button on a served
community row (which adds exactly that value). The value is stored, the
in-memory gate cache is refreshed immediately, and the object is withheld from
the next poll. Every add/remove is audited (`benign.create` / `benign.delete`).

Only **community** objects are gated, so a benign entry never affects manually-fed
intel (`source='manual'`), which is always served.

A malformed config entry (e.g. a bad CIDR in `benign_cidrs`) is logged and
skipped rather than failing startup — a typo in the list must not take the
feed down.

### Example config

```yaml
intel_filter:
  community_sources: []          # default: gate ALL non-manual sources
  # community_sources: ['otx']   # or gate only these named sources
  drop_private_ips: true         # drop non-routable IPs (biggest noise reducer)
  freshness_days: 30             # drop community intel older than 30 days
  min_confidence: null           # set e.g. 80 to enforce a confidence floor
  blocklist: []                  # e.g. ['example.com', '198.51.100.20']
  # Known-legitimate filter — keep real values OUT of the feed.
  benign_values: []              # e.g. ['8.8.8.8', 'login.microsoftonline.com']
  benign_domains: []             # e.g. ['microsoft.com', 'gov.sg']  (+ subdomains)
  benign_cidrs: []               # e.g. ['13.107.0.0/16']  (CIDR is supported here)
```

> **Blocklist note:** the blocklist matches **single exact values** (not CIDR
> ranges) — `10.20.30.40` matches that IP, but `10.20.0.0/16` does *not*
> expand to a range. The `drop_private_ips` rule already covers the whole
> private space; use the blocklist for specific *public* values you always
> want to exclude. Use `benign_cidrs` when you need a **range** on the
> known-legitimate side.

#### Triage loop for a false positive

1. A legitimate domain or IP is being **served** (Vision One may block it) →
   open the **Feed** tab and find the row.
2. Click **Exclude** on that row — or add the value (as *exact* / *domain* /
   *cidr*) in the **Known-legitimate filter** panel.
3. It is withheld from the next poll, and the entry is now visible in the panel
   and the **Audit log** (`benign.create`).
4. Prefer a durable, reviewable rule in `config.yaml` for anything your team
   agrees should *always* be excluded; use the dashboard for quick, one-off
   exclusions.

## Testing

Run the test suite:

```bash
python tests/test_server.py
```

This covers all TAXII 2.1 endpoints, **Get Objects pagination**
(`limit` / `next` / `more`, keyset consistency, `400`s on malformed
params), **extended STIX object types** (url / email-addr / ipv6-addr /
mac-addr / windows-registry-key / autonomous-system), **the STIX graph**
(relationship / malware / threat-actor / campaign ingest + serving,
third-party puller mapping, community-sourced gating of the new types),
**multi-collection RBAC** (per-collection credentials, scoped collection
listing, isolated Get Objects, collection-scoped data endpoints and
purge), ingestion (replace + merge modes, validation skipping), Excel
(**.xlsx**) + CSV import (fuzzy header mapping, indicator-column URL/IPv6
promotion, merge-not-replace, auth, bad-input handling),
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
floor, blocklist, and that manual intel is never gated), the
**known-legitimate filter** (config `benign_values`/`benign_domains`/`benign_cidrs`
and the dynamic ones withholding matching community objects; the one-click
`POST /objects/<id>/exclude` and `/ui/benign` CRUD; write-role gating;
value/kind validation; idempotency; and audit), **manual
revocation** (`POST /objects/<id>/revoke`, stickiness across saves,
`revoked: true` in the TAXII bundle) and **TTL auto-revocation** (per-type
aging sweep), and **SSO** (Microsoft Entra OIDC: PKCE authorize redirect +
challenge math, signed-state CSRF rejection, real RS256 ID-token
validation against a local key for signature/audience/nonce, domain/UPN/
group allow-lists, and session-cookie issuance on success).

## Security Considerations

- Use **HTTPS/TLS** for production deployments (configurable via reverse proxy).
- **Set strong `ui.auth` / `taxii.auth` credentials** in `.env`
  (`UI_AUTH_USER`/`UI_AUTH_PASSWORD`, `TAXII_AUTH_USER`/`TAXII_AUTH_PASSWORD`)
  and change them from the default `admin`/`admin`.
- **Privilege split (enforced in code).** `taxii.auth` is a **read-only**
  consumer credential — it can poll `/taxii2/` but not ingest, delete, revoke
  or purge. Every write needs the **dashboard session**, the **UI
  credentials** (`curl -u "$UI_AUTH_USER:$UI_AUTH_PASSWORD"`) or an optional
  **`taxii.admin_auth`** principal (`.env`: `TAXII_ADMIN_USER`/
  `TAXII_ADMIN_PASSWORD`, config: `taxii.admin_auth`). So a leaked Vision One
  credential cannot change the feed.
- **Set `FLASK_SECRET`** (in `.env`; it's required — no default) — the UI
  session cookie is signed with it; an unset value leaves cookies unsigned
  and lets a forged cookie authenticate to the data endpoints.
- Use strong, unique passwords and store them hashed.
- **SSO:** assign the Entra app to a specific group (not "all users") so only
  authorized operators can sign in; set `sso.redirect_uri` to match the
  registered redirect URI exactly; keep `client_secret` out of version
  control (env var); and require **HTTPS** for the production redirect URI.
  Local `http://localhost` is only for testing.
- Set `debug: false` in production.

**What the server does for you (`server.py`)**

| Control | Behavior |
|---------|----------|
| Response headers | Every response carries `Content-Security-Policy` (inline script/style allowed, everything else `'self'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Strict-Transport-Security`. |
| Session cookie | `taxii2_ui_session` is `HttpOnly`, `SameSite=Lax`, `Secure`, signed (itsdangerous) and time-bounded (`ui.session_ttl`). It carries the username *and* how the session was established, never the role: the role is re-resolved from `ui_users` on every request, so revoking access is immediate. |
| Roles | Dashboard writes need `editor`; API-key and user management need `admin`. The last enabled admin cannot be removed. `ui.auth` and `taxii.admin_auth` are always admin (break-glass). |
| Upload caps | `/feed/import-csv` bodies are capped at `security.max_upload_bytes` (25 MB → `413`) and parsed at most `security.max_import_rows` rows (50 000) before truncating with a note. A workbook that fails to parse returns a generic `400` (parser detail stays in the log), and `defusedxml` hardens openpyxl's XML parsing of untrusted `.xlsx`. |
| Response caps | `/objects` accepts `?limit=` and never returns more than `security.max_objects_json` rows (50 000), reporting `"truncated": true` when it trims. TAXII Get Objects is capped at `taxii.max_objects` (10 000) per response **even when the client sends no `?limit=`**, so a single poll cannot materialise a whole collection; the client continues via `more`/`next`. Set `taxii.max_objects: 0` to disable. |
| Auth throttling | After `security.auth_fail_limit` (10) failed credentials from one client IP within `security.auth_fail_window` (300 s), further attempts get `429` + `Retry-After` without the credential being evaluated. Only requests that *present* a credential are counted, and a success clears the counter. The failure table is bounded by evicting its oldest keys — never cleared wholesale, so a caller able to vary its throttle key cannot reset protection for everyone. |
| Error bodies | 5xx responses return a generic message; driver/exception text goes to the server log only. |
| CORS | `server.cors_origins` — pin it to your real origin(s). `'*'` reflects any origin (dev only; still no `Allow-Credentials`, so browser reads cannot use a session cookie). |
| Input validation | All SQL goes through the ORM (no string-built SQL); STIX ids are shape-checked (`<type>--<id>`, type-prefix match); uploaded/ingested values are stored as data (ids derived, never taken from input — see [upload sanitization](#sanitization--injection-behaviour-of-the-upload-field)); dashboard values are rendered with `textContent`/escaping; the SSO error page HTML-escapes caller input. |
| Audit | Successful imports, deletes and revokes log the count/target plus the client IP (`CF-Connecting-IP`). |
| Client IP | Throttling keys and log lines use `CF-Connecting-IP` / `X-Forwarded-For`, but **only when the request arrives from a `security.trusted_proxies` network** (default: loopback + the compose ranges). From any other peer the header is ignored and the connection's own address is used, so a caller reaching the origin directly cannot spoof its throttle identity. Set `security.trusted_proxies: []` to trust no proxy. |

> **Upgrading from an older build:** writes used to accept plain TAXII
> credentials. If a script relied on that, switch it to the UI credentials
> (`-u "$UI_AUTH_USER:$UI_AUTH_PASSWORD"`) or set `taxii.admin_auth`.

## Environment Variables

### `.env` file (recommended for secrets)

`server.py` loads a `.env` file at startup (built-in minimal loader — no
`python-dotenv` dependency). Copy the template and fill it in:

```bash
cp .env.example .env
# edit .env: set FLASK_SECRET and (for SSO) SSO_CLIENT_SECRET
```

Rules:

- **Location:** `.env` next to `server.py`, or point `TAXII_ENV_FILE` at a
  different path.
- **Process env always wins** over `.env` — `export FOO=...` in your shell
  (or a systemd `Environment=`) still overrides the file.
- A missing `.env` is fine; `${VAR:-default}` fallbacks in `config.yaml` apply.
- `.env` is **git-ignored**. The committed `.env.example` holds the keys
  with empty values + comments; real values live only on the host.

| Variable | Default | Description |
|----------|---------|-------------|
| `TAXII_CONFIG` | `./config.yaml` | Path to configuration file |
| `TAXII_ENV_FILE` | `./.env` (next to server.py) | Path to the .env file |
| `FLASK_SECRET` | *(required, no default)* | Flask secret key (signs UI session + SSO state cookies) — set in `.env` |
| `TAXII_AUTH_USER` / `TAXII_AUTH_PASSWORD` | *(no default)* | TAXII client credentials (`taxii.auth`) — what Vision One uses on `/taxii2/`. **Read-only**: cannot ingest/delete/revoke/purge. Unset → startup warning; `/taxii2/` rejects all clients |
| `UI_AUTH_USER` / `UI_AUTH_PASSWORD` | *(no default)* | Dashboard login credentials (`ui.auth`) and a valid write credential for scripts (`curl -u`). Unset → startup warning; `/ui/login` fails closed (503) |
| `TAXII_ADMIN_USER` / `TAXII_ADMIN_PASSWORD` | *(empty)* | Optional feed-wide **write** principal (`taxii.admin_auth`) for automation that shouldn't use the dashboard login. Empty → only the dashboard session/UI credentials can write |
| `DATABASE_URL` | `sqlite:///taxii_feed.db` | Database connection URL (set to e.g. `postgresql+psycopg2://taxii:...@127.0.0.1:5432/taxii_feed` to run on PostgreSQL) |
| `OTX_API_KEY` | *(empty)* | Optional AlienVault OTX API key (`otx.api_key` in config.yaml, `${OTX_API_KEY:-}`). Free key from otx.alienvault.com raises the public read-only rate limits; empty = anonymous browsing (throttled) |
| `TAXII_OBJECTS_SHAPE` | `bundle` | Get Objects response shape (`taxii.objects_shape`): `bundle` (default — OTX-compatible `{type,objects,more,next}`, no envelope; **what Vision One ingests**) or `envelope` (spec TAXII 2.1 Message Resource, §5.3 — set this only for a spec-strict client). |
| `SSO_CLIENT_SECRET` | *(empty)* | Microsoft Entra client secret (referenced by `sso.client_secret` in config.yaml) |

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
  `freshness_days`, a low-confidence one trips `min_confidence`, a
  listed value trips `blocklist`, and a legit value trips the
  known-legitimate filter.
- If it's a **legitimate domain or IP you don't want served** (Vision One would
  block it), exclude it without a restart: click **Exclude** on the row in the
  feed, or add the value in the **Known-legitimate filter** panel (`exact` /
  `domain` / `cidr`). It is withheld from the next poll — see
  [The known-legitimate filter](#the-known-legitimate-filter-keeping-legit-values-out-of-the-feed).
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

> **Implemented since this list was written:** `limit`/`next` pagination on
> Get Objects (now spec §5.3 keyset pagination), Excel (.xlsx) import, extra
> STIX 2.1 object types (url / email-addr / ipv6-addr / mac-addr /
> windows-registry-key / autonomous-system), a real STIX graph subset
> (relationships + malware / threat-actor / campaign), and multiple
> collections with per-client credentials (RBAC). See the relevant sections
> above.

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
- **Full STIX 2.1 graph** (the whole SDO/SRO catalog: `attack-pattern`,
  `tool`, `infrastructure`, `intrusion-set`, `campaign`-to-indicator link
  tables, object-level `created_by_ref`) — the store now supports
  relationships + the core SDOs; a complete catalog is a model-level
  extension of the same pattern.

## License

MIT License
