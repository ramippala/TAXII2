#!/usr/bin/env python3
"""
TAXII 2.1 Server for STIX 2.1 Threat Intelligence Feed
Feeds custom threat intelligence (IP addresses, file hashes, FQDNs) to
Trend Micro Vision One (a TAXII 2.1 client) via the /taxii2/ endpoint.

Architecture:
    Flask API (TAXII 2.1 + REST)  -->  Memory + SQLite/Postgres store (STIX 2.1)
        |
        |  <-- Trend Micro Vision One polls /taxii2/ (external TAXII 2.1 client)
        |
    Optional background pollers (both off by default):
        - otx        : pull community intel FROM AlienVault OTX (pulses/indicators)
        - self_check : self-test that polls our own /feed for reachability
"""

import base64
import csv
import hashlib
import io
import ipaddress
import json
import logging
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from flask import (Flask, Response, jsonify, make_response, redirect,
                   request, send_from_directory)
from flask_cors import CORS
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
    Text,
    create_engine,
    text,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Configuration Loading
# ---------------------------------------------------------------------------

CONFIG_PATH = Path(os.environ.get('TAXII_CONFIG', str(Path(__file__).parent / 'config.yaml')))

_ENV_VAR_RE = re.compile(r'\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}')


def _dotenv_path() -> Path:
    """Where the app looks for .env: $TAXII_ENV_FILE, else ./.env next to server.py."""
    return Path(os.environ.get('TAXII_ENV_FILE', str(Path(__file__).resolve().parent / '.env')))


def _load_dotenv(path: Path) -> None:
    """Load KEY=VALUE lines from a .env file into the process environment.

    Minimal on purpose (no python-dotenv, stays offline/zero-dep).
    - Process env vars ALWAYS win: existing keys are never overwritten.
    - Blank lines and '#' comments are skipped; a missing file is a no-op.
    - Values may be wrapped in single or double quotes.
    """
    try:
        if not path.is_file():
            return
        with open(path, 'r', encoding='utf-8-sig') as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, _, value = line.partition('=')
                key = key.strip()
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                    value = value[1:-1]
                if key and key not in os.environ:
                    os.environ[key] = value
    except OSError as exc:
        print(f'WARNING: could not read .env file {path}: {exc}', file=sys.stderr)


def _resolve_value(value: Any) -> Any:
    """Resolve ${ENV_VAR} and ${ENV_VAR:-default} placeholders in config values."""
    if isinstance(value, str):
        return _ENV_VAR_RE.sub(
            lambda m: os.environ.get(m.group(1), m.group(2) if m.group(2) is not None else ''),
            value,
        )
    if isinstance(value, dict):
        return {k: _resolve_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_value(v) for v in value]
    return value


def load_config() -> Dict[str, Any]:
    """Load configuration from YAML file.

    A .env file is loaded into the environment first (if present) so that
    ${ENV_VAR} / ${ENV_VAR:-default} placeholders below resolve against it.
    Process env vars always take precedence over .env values.
    """
    _load_dotenv(_dotenv_path())
    with open(CONFIG_PATH, 'r') as fh:
        raw = yaml.safe_load(fh) or {}
    return _resolve_value(raw)


CONFIG = load_config()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=getattr(logging, str(CONFIG.get('logging', {}).get('level', 'INFO')).upper(), logging.INFO),
    format=CONFIG.get('logging', {}).get('format', '[%(asctime)s] %(levelname)s: %(message)s'),
)
logger = logging.getLogger('TAXII')

# ---------------------------------------------------------------------------
# Database Setup
# ---------------------------------------------------------------------------

DB_CFG = CONFIG.get('database', {}) or {}
DATABASE_URL = DB_CFG.get('url', 'sqlite:///taxii_feed.db')
_CONN_TIMEOUT = int(DB_CFG.get('connection_timeout', 30))

_ENGINE_KW: Dict[str, Any] = {
    'echo': False,
    'pool_pre_ping': True,       # drop dead connections before reuse
    'pool_recycle': 300,         # recycle before most DBs idle-timeout
    'pool_timeout': _CONN_TIMEOUT,
}
if DATABASE_URL.startswith('sqlite'):
    # In-process store: allow the poller threads to share connections.
    _ENGINE_KW['connect_args'] = {'check_same_thread': False}
else:
    # Server database (PostgreSQL / MariaDB / MySQL): sized connection pool.
    _ENGINE_KW.update(
        pool_size=int(DB_CFG.get('pool_size', 5)),
        max_overflow=int(DB_CFG.get('max_overflow', 10)),
    )

try:
    engine = create_engine(DATABASE_URL, **_ENGINE_KW)
except ImportError as exc:
    logger.error(
        "Database driver missing for URL %r (%s). Install it with "
        "`pip install` — e.g. psycopg2-binary (PostgreSQL) or "
        "PyMySQL/mysqlclient (MariaDB/MySQL).",
        DATABASE_URL, exc,
    )
    raise
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

Base = declarative_base()


class STIXObject(Base):
    """ORM model for STIX objects persisted to database."""

    __tablename__ = "stix_objects"

    id = Column(String, primary_key=True, index=True)
    stix_id = Column(String, unique=True, nullable=False, index=True)
    object_type = Column(String, nullable=False, index=True)
    name = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    labels = Column(String, nullable=True)  # comma-separated
    confidence = Column(Integer, default=0)
    hash_value = Column(String, nullable=True)  # file hash
    ip_address = Column(String, nullable=True)   # IP address
    domain = Column(String, nullable=True)       # FQDN
    source = Column(String, nullable=True)       # origin: 'manual' | 'otx'
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    revoked = Column(Boolean, default=False)
    revoked_at = Column(DateTime, nullable=True)   # when it was revoked (UTC)
    created = Column(DateTime, default=datetime.utcnow)
    modified = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Subscription(Base):
    """ORM model for TAXII subscriptions."""

    __tablename__ = "subscriptions"

    id = Column(String, primary_key=True)
    client_id = Column(String, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    enabled = Column(Boolean, default=True)
    created = Column(DateTime, default=datetime.utcnow)
    last_verified = Column(DateTime, nullable=True)


class PullerState(Base):
    """Per-community-puller state: last sync timestamp + status.

    Lets the OTX / TAXII pullers resume from where they left off (``?since=``
    delta polling) across restarts, and exposes the last run to the dashboard.
    """

    __tablename__ = "puller_state"

    id = Column(String, primary_key=True)          # e.g. 'otx' or 'taxii:<name>'
    last_sync = Column(DateTime, nullable=True)     # last successful poll (UTC)
    last_added = Column(Integer, default=0)         # objects added on last poll
    last_status = Column(String, nullable=True)     # 'ok' | 'error'
    last_message = Column(String, nullable=True)    # error detail / summary
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


def _utc_now_iso() -> str:
    """Current UTC time as ISO-8601 'Z' (STIX 2.1 / TAXII ?since= format)."""
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')


def create_session():
    """Create a new database session (caller is responsible for closing)."""
    return SessionLocal()


def init_db() -> None:
    """Initialize database tables (and apply lightweight column migrations)."""
    Base.metadata.create_all(engine)
    # Lightweight migration for databases created before the `source` column
    # existed (no ORM migrations installed; add-if-missing is idempotent).
    from sqlalchemy import inspect
    insp = inspect(engine)
    if 'stix_objects' in insp.get_table_names():
        cols = {c['name'] for c in insp.get_columns('stix_objects')}
        # Databases created before these columns existed (idempotent).
        if 'source' not in cols:
            with engine.begin() as conn:
                conn.execute(text('ALTER TABLE stix_objects ADD COLUMN source VARCHAR'))
            logger.info("Migrated stix_objects: added 'source' column")
        if 'revoked_at' not in cols:
            with engine.begin() as conn:
                conn.execute(
                    text('ALTER TABLE stix_objects ADD COLUMN revoked_at DATETIME')
                )
            logger.info("Migrated stix_objects: added 'revoked_at' column")
    logger.info("Database initialized")


def rehydrate_memory() -> int:
    """Load persisted STIX objects back into the in-memory store.

    The memory store is the fast path for TAXII polls, but it is volatile:
    after a restart the feed would otherwise appear empty to Vision One until
    the next ingest. Rebuilding it from the DB makes ingested intel survive
    restarts. Returns the number of objects reloaded.
    """
    session = create_session()
    try:
        rows = session.query(STIXObject).all()
        with memory_lock:
            for row in rows:
                if row.stix_id in memory_store:
                    continue
                labels = [l for l in (row.labels or '').split(',') if l]
                memory_store[row.stix_id] = ThreatIntel(
                    stix_id=row.stix_id,
                    object_type=row.object_type,
                    labels=labels,
                    confidence=row.confidence or 0,
                    name=row.name,
                    description=row.description,
                    hash_value=row.hash_value,
                    ip_address=row.ip_address,
                    domain=row.domain,
                    source=row.source or 'manual',
                    revoked=bool(row.revoked),
                )
            count = len(memory_store)
    finally:
        session.close()
    if count:
        logger.info("Rehydrated %s object(s) from database into memory", count)
    return count


# ---------------------------------------------------------------------------
# Indicator TTL / auto-revocation (lifecycle & aging)
# ---------------------------------------------------------------------------
# Per-type time-to-live: dynamic indicators age out and are auto-REVOKED
# (served to Vision One as STIX revoked: true, so clients purge them) rather
# than deleted. IPs expire fast, file hashes stay much longer. Set
# lifecycle.enabled: false (or a type's days to null) to disable.

LIFECYCLE_CFG = CONFIG.get('lifecycle', {}) or {}
LIFECYCLE_ENABLED = bool(LIFECYCLE_CFG.get('enabled', True))
LIFECYCLE_SWEEP_INTERVAL = int(LIFECYCLE_CFG.get('sweep_interval', 3600))  # seconds
# days, by type class (null = no TTL for that type)
LIFECYCLE_TTL_DAYS: Dict[str, Optional[int]] = {
    'ipv4-addr': LIFECYCLE_CFG.get('ipv4_days', 14),
    'domain-name': LIFECYCLE_CFG.get('domain_days', 30),
    'file-hash': LIFECYCLE_CFG.get('file_days', 180),
    'indicator': LIFECYCLE_CFG.get('indicator_days', 30),
}


def _ttl_days_for(object_type: str) -> Optional[int]:
    """TTL in days for an object type, or None (no TTL)."""
    days = LIFECYCLE_TTL_DAYS.get(object_type, None)
    if isinstance(days, int) and days > 0:
        return days
    return None


def sweep_expired_indicators(now: Optional[datetime] = None) -> int:
    """Auto-revoke objects past their per-type TTL.

    Revoked (not deleted) objects stay in the DB and are *served* with
    ``revoked: true`` so TAXII clients (Vision One) can drop them. Returns
    the number of newly revoked objects.
    """
    if not LIFECYCLE_ENABLED:
        return 0
    now = now or datetime.utcnow()
    session = create_session()
    try:
        rows = session.query(STIXObject).filter_by(revoked=False).all()
        newly = 0
        for row in rows:
            days = _ttl_days_for(row.object_type or '')
            if days is None:
                continue
            anchor = row.last_seen or row.first_seen or row.modified
            if anchor is None:
                continue
            if (now - anchor) > timedelta(days=days):
                row.revoked = True
                row.revoked_at = now
                with memory_lock:
                    obj = memory_store.get(row.stix_id)
                    if obj is not None:
                        obj.revoked = True
                newly += 1
        if newly:
            session.commit()
            logger.info(
                "TTL sweep auto-revoked %s expired indicator(s)", newly
            )
        return newly
    except Exception as exc:
        session.rollback()
        logger.error("TTL sweep failed: %s", exc)
        return 0
    finally:
        session.close()


def start_ttl_sweeper() -> None:
    """Background thread that periodically auto-revokes expired objects."""
    if not LIFECYCLE_ENABLED:
        return

    def _loop() -> None:
        while True:
            try:
                time.sleep(LIFECYCLE_SWEEP_INTERVAL)
                sweep_expired_indicators()
            except Exception:  # pragma: no cover - best-effort loop guard
                pass

    thread = threading.Thread(target=_loop, name='TtlSweeper', daemon=True)
    thread.start()
    logger.info(
        "TTL sweeper started (interval=%ss, ttl_days=%s)",
        LIFECYCLE_SWEEP_INTERVAL, LIFECYCLE_TTL_DAYS,
    )


# ---------------------------------------------------------------------------
# Community-puller state (persisted ?since= delta + status for the dashboard)
# ---------------------------------------------------------------------------

def save_puller_state(puller_id: str, status: str, added: int = 0,
                      message: Optional[str] = None) -> None:
    """Persist a puller's last-run state (used for ?since= resume + UI)."""
    session = create_session()
    try:
        row = session.query(PullerState).filter_by(id=puller_id).first()
        if row is None:
            row = PullerState(id=puller_id)
            session.add(row)
        row.last_sync = datetime.utcnow()
        row.last_added = int(added or 0)
        row.last_status = status
        row.last_message = message
        session.commit()
    except Exception as exc:  # pragma: no cover - persistence is best-effort
        session.rollback()
        logger.error("Failed to save puller state %s: %s", puller_id, exc)
    finally:
        session.close()


def read_puller_state(puller_id: str) -> Optional[Dict[str, Any]]:
    """Read a puller's persisted state dict (or None if never run)."""
    session = create_session()
    try:
        row = session.query(PullerState).filter_by(id=puller_id).first()
        if row is None:
            return None
        return {
            'last_sync': row.last_sync.isoformat() + 'Z' if row.last_sync else None,
            'last_added': row.last_added or 0,
            'last_status': row.last_status,
            'last_message': row.last_message,
        }
    finally:
        session.close()


def _puller_since_iso(puller_id: str) -> Optional[str]:
    """Return the last-sync time as an ISO 'Z' string for ?since=, or None
    (meaning a full pull) if the puller has never synced."""
    st = read_puller_state(puller_id)
    if not st or not st.get('last_sync'):
        return None
    # last_sync is 'YYYY-MM-DDTHH:MM:SS.ffffffZ' — drop microseconds for ?since=
    return st['last_sync'].split('.')[0] + 'Z'


# ---------------------------------------------------------------------------
# STIX 2.1 Object Model
# ---------------------------------------------------------------------------

@dataclass
class ThreatIntel:
    """Threat intelligence object in STIX 2.1 format."""

    stix_id: str
    object_type: str
    labels: List[str] = field(default_factory=list)
    confidence: int = 0
    name: Optional[str] = None
    description: Optional[str] = None
    hash_value: Optional[str] = None
    ip_address: Optional[str] = None
    domain: Optional[str] = None
    source: str = 'manual'
    revoked: bool = False  # once revoked -> served as STIX revoked: true

    def to_stix_object(self) -> Dict[str, Any]:
        """Convert to a STIX 2.1-flavoured object dict (see generate_taxii_bundle)."""
        labels = self.labels or []
        confidence = self.confidence or 0
        now = datetime.utcnow().isoformat()

        obj_dict: Dict[str, Any] = {}
        if self.object_type == "ipv4-addr":
            obj_dict["value"] = self.ip_address or self.stix_id
        elif self.object_type == "file-hash":
            obj_dict["hash_value"] = {
                "algorithm": labels[0] if labels else "sha256",
                "value": self.hash_value or self.stix_id,
            }
        elif self.object_type == "domain-name":
            obj_dict["value"] = self.domain or self.stix_id
        elif self.object_type in ("indicator", "malware", "malware-family"):
            obj_dict["value"] = self.name or "Threat Intel Indicator"
        else:
            obj_dict["value"] = self.stix_id

        result: Dict[str, Any] = {
            "id": self.stix_id,
            "type": self.object_type,
            "created": now,
            "modified": now,
            "revoked": bool(self.revoked),
            "labels": labels,
            "confidence": confidence,
            "object": obj_dict,
        }
        # Keep the hash addressable at the top level as well (consumers differ).
        if self.object_type == "file-hash":
            result["hash_value"] = obj_dict["hash_value"]
        return result


# In-memory store (primary for fast polling)
memory_store: Dict[str, ThreatIntel] = {}
memory_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Flask Application
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config['SECRET_KEY'] = CONFIG.get('security', {}).get(
    'secret_key', 'dev-secret-key-change-in-production'
)
_taxii_auth_cfg = CONFIG.get('taxii', {}).get('auth', {}) or {}
app.config['TAXII_AUTH'] = {
    'username': _taxii_auth_cfg.get('username') or '',
    'password': _taxii_auth_cfg.get('password') or '',
}
_cors_origins = (CONFIG.get('server', {}) or {}).get('cors_origins') or ['*']
CORS(app, origins=_cors_origins)


# ---------------------------------------------------------------------------
# TAXII 2 Authentication
# ---------------------------------------------------------------------------

def _get_taxii_auth_config() -> Dict[str, str]:
    """Get TAXII 2 authentication credentials (app.config overridable in tests)."""
    auth = app.config.get('TAXII_AUTH') or {}
    return {
        'username': auth.get('username', ''),
        'password': auth.get('password', ''),
    }


def _request_taxii_credentials() -> Tuple[str, str]:
    """Extract TAXII credentials from the request (custom headers or Basic auth)."""
    username = request.headers.get('X-Taxii-Username', '')
    password = request.headers.get('X-Taxii-Password', '')
    if not username:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.lower().startswith('basic '):
            try:
                decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
                username, _, password = decoded.partition(':')
            except Exception:
                username, password = '', ''
    return username or '', password or ''


def _validate_taxii_auth(client_user: str, client_pass: str) -> bool:
    """Validate TAXII 2 authentication credentials."""
    auth = _get_taxii_auth_config()
    if not auth.get('username'):
        return False
    return (
        client_user == auth.get('username')
        and client_pass == auth.get('password')
    )


# ---------------------------------------------------------------------------
# Web UI session auth (separate from TAXII credentials)
# ---------------------------------------------------------------------------

UI_CFG = CONFIG.get('ui', {}) or {}
UI_AUTH = UI_CFG.get('auth', {}) or {}
_ui_username = str(UI_AUTH.get('username') or 'admin')
_ui_password = str(UI_AUTH.get('password') or 'admin')
_ui_secret = str(CONFIG.get('security', {}).get('secret_key', 'dev-secret-key-change-in-production'))
_ui_session_ttl = int(UI_CFG.get('session_ttl', 43200))  # seconds (default 12 h)

from itsdangerous import BadSignature, URLSafeTimedSerializer

_session_serializer = URLSafeTimedSerializer(_ui_secret, salt='taxii2-ui-session')


def _session_cookie(username: str) -> str:
    """Create a signed, time-bounded session cookie for the web UI."""
    return _session_serializer.dumps({'user': username})


def _session_user() -> Optional[str]:
    """Decode the session cookie; returns the username or None."""
    token = request.cookies.get('taxii2_ui_session')
    if not token:
        return None
    try:
        payload = _session_serializer.loads(token, max_age=_ui_session_ttl)
        return payload.get('user')
    except BadSignature:
        return None


def _ui_session_valid() -> bool:
    return _session_user() is not None


def _request_allowed() -> bool:
    """Data endpoints accept TAXII credentials (scripts / Vision One,
    unchanged) OR a valid web-UI session cookie (browser)."""
    user, pw = _request_taxii_credentials()
    if _validate_taxii_auth(user, pw):
        return True
    return _ui_session_valid()


# ---------------------------------------------------------------------------
# SSO — Microsoft Entra ID (Azure AD) via OIDC Authorization Code + PKCE
# ---------------------------------------------------------------------------
# Optional, OFF by default (sso.enabled: false). When enabled, the UI offers
# "Sign in with Microsoft". Local username/password login remains as a
# fallback so the box is never locked out if the IdP is unreachable.
#
# Flow: browser -> /ui/sso -> Microsoft /oauth2/v2.0/authorize (user picks an
# account; Entra app assignment restricts to your tenant group) -> Microsoft
# redirects to /ui/sso/callback?code=...&state=... -> THIS server exchanges
# the code for a token server-side (egress to login.microsoftonline.com only),
# validates the ID-token JWT (JWKS signature + iss/aud/exp/nonce), applies the
# allow-list, then issues the SAME taxii2_ui_session cookie as local login.
#
# Only `requests`, `jwt`, `cryptography` (already required) are used.

try:  # SSO-only dependencies; the server boots without them when SSO is off.
    import jwt
except ImportError:  # pragma: no cover - depends on optional install
    jwt = None

try:
    import requests as _http_requests
except ImportError:  # pragma: no cover - depends on optional install
    _http_requests = None

SSO_CFG = CONFIG.get('sso', {}) or {}
SSO_ENABLED = bool(SSO_CFG.get('enabled', False))
SSO_TENANT = str(SSO_CFG.get('tenant', 'common') or 'common')
SSO_CLIENT_ID = str(SSO_CFG.get('client_id', '') or '')
SSO_CLIENT_SECRET = str(SSO_CFG.get('client_secret', '') or '')
SSO_REDIRECT_URI = str(SSO_CFG.get('redirect_uri', '') or '')
SSO_AUTH_ENDPOINT = str(
    SSO_CFG.get('authorization_endpoint',
               f'https://login.microsoftonline.com/{SSO_TENANT}/oauth2/v2.0/authorize')
)
SSO_TOKEN_ENDPOINT = str(
    SSO_CFG.get('token_endpoint',
               f'https://login.microsoftonline.com/{SSO_TENANT}/oauth2/v2.0/token')
)
SSO_JWKS_ENDPOINT = str(
    SSO_CFG.get('jwks_uri',
               f'https://login.microsoftonline.com/{SSO_TENANT}/discovery/v2.0/keys')
)
# Expected issuer (validated on the ID token). Empty = auto (use JWKS host).
SSO_ISSUER = str(SSO_CFG.get('issuer', '') or '')
SSO_ALLOW_DOMAINS = tuple(d.lower() for d in (SSO_CFG.get('allowed_domains') or []) if d)
SSO_ALLOW_UPNS = set(u.lower() for u in (SSO_CFG.get('allowed_upns') or []) if u)
SSO_ALLOW_GROUPS = set(g for g in (SSO_CFG.get('allowed_groups') or []) if g)
SSO_SCOPES = 'openid profile email'

# Short-lived signed cookie that carries the OAuth temp state (CSRF + PKCE).
_oauth_state_serializer = URLSafeTimedSerializer(
    _ui_secret, salt='taxii2-ui-sso'
)
_oauth_state_cookie = 'taxii2_ui_sso'

# Cached JWKS client (fetches + caches Microsoft's signing keys, rotates).
_sso_jwks_client = None


def _sso_jwks():
    global _sso_jwks_client
    if _sso_jwks_client is None:
        _sso_jwks_client = jwt.PyJWKClient(SSO_JWKS_ENDPOINT)
    return _sso_jwks_client


def _sso_expected_issuer() -> str:
    if SSO_ISSUER:
        return SSO_ISSUER
    # Fall back to the tenant discovery issuer.
    return f'https://login.microsoftonline.com/{SSO_TENANT}/v2.0'


def _sso_user_allowed(claims: Dict[str, Any]) -> Tuple[bool, str]:
    """Apply the SSO allow-list. Returns (allowed, reason).

    Entra app assignment is the primary gate (only assigned users can even
    sign in). These server-side checks are defense-in-depth:
      * allowed_domains  -> email/preferred_username domain must be listed
      * allowed_upns     -> full UPN/email must be listed (exact)
      * allowed_groups   -> token 'groups' claim must intersect (if present)
    With all allow-lists empty, any valid tenant user passes (assignment-only).
    """
    email = str(
        claims.get('preferred_username') or claims.get('upn')
        or claims.get('email') or ''
    ).lower()
    domain = email.split('@')[-1] if '@' in email else ''

    if SSO_ALLOW_UPNS and email not in SSO_ALLOW_UPNS:
        return False, 'not in allowed users'
    if SSO_ALLOW_DOMAINS and domain not in SSO_ALLOW_DOMAINS:
        return False, 'domain not allowed'
    if SSO_ALLOW_GROUPS:
        groups = claims.get('groups') or []
        if not (set(str(g) for g in groups) & SSO_ALLOW_GROUPS):
            return False, 'not in an allowed Entra group'
    return True, ''


def _sso_validate_id_token(token: str, expected_nonce: str) -> Dict[str, Any]:
    """Validate the ID-token JWT against Microsoft's JWKS. Returns claims.

    Raises jwt.InvalidTokenError (or subclass) on any failure.
    """
    signing_key = _sso_jwks().get_signing_key_from_jwt(token)
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=['RS256'],
        audience=SSO_CLIENT_ID,
        issuer=_sso_expected_issuer(),
        options={'require': ['exp', 'iss', 'aud', 'sub']},
    )
    # Nonce binds the token to this login attempt (replay protection).
    if expected_nonce and claims.get('nonce') != expected_nonce:
        raise jwt.InvalidTokenError('nonce mismatch')
    return claims


def _sso_exchange_code(code: str, code_verifier: str) -> Dict[str, Any]:
    """Exchange the authorization code for tokens (server-side)."""
    data = {
        'client_id': SSO_CLIENT_ID,
        'client_secret': SSO_CLIENT_SECRET,
        'code': code,
        'redirect_uri': SSO_REDIRECT_URI,
        'grant_type': 'authorization_code',
        'code_verifier': code_verifier,
        'scope': SSO_SCOPES,
    }
    resp = _http_requests.post(
        SSO_TOKEN_ENDPOINT, data=data, timeout=30,
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
    )
    resp.raise_for_status()
    return resp.json()


def _sso_oauth_state_token(payload: Dict[str, Any]) -> str:
    return _oauth_state_serializer.dumps(payload)


def _sso_read_oauth_state() -> Optional[Dict[str, Any]]:
    raw = request.cookies.get(_oauth_state_cookie)
    if not raw:
        return None
    try:
        return _oauth_state_serializer.loads(raw, max_age=600)
    except BadSignature:
        return None


def _sso_deps_ok() -> bool:
    return jwt is not None and _http_requests is not None


@app.route('/ui/sso', methods=['GET'])
def ui_sso_start():
    """GET /ui/sso — begin the Microsoft OIDC login (Authorization Code + PKCE)."""
    if not SSO_ENABLED:
        return jsonify({'error': 'SSO is not enabled'}), 404
    if not _sso_deps_ok():
        logger.error("SSO enabled but PyJWT/requests are not installed")
        return jsonify({'error': 'SSO dependencies missing'}), 500
    state = uuid.uuid4().hex
    nonce = uuid.uuid4().hex
    code_verifier = uuid.uuid4().hex + uuid.uuid4().hex  # 64+ chars
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).rstrip(b'=').decode('ascii')

    params = {
        'client_id': SSO_CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': SSO_REDIRECT_URI,
        'scope': SSO_SCOPES,
        'state': state,
        'nonce': nonce,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
        'response_mode': 'query',
    }
    sep = '&' if '?' in SSO_AUTH_ENDPOINT else '?'
    resp = redirect(SSO_AUTH_ENDPOINT + sep + urllib.parse.urlencode(params))
    # Carry the temp state in a short-lived signed cookie (CSRF + PKCE binding).
    resp.set_cookie(
        _oauth_state_cookie,
        _sso_oauth_state_token({'state': state, 'nonce': nonce,
                                'code_verifier': code_verifier}),
        max_age=600, httponly=True, samesite='Lax',
    )
    return resp


@app.route('/ui/sso/callback', methods=['GET'])
def ui_sso_callback():
    """GET /ui/sso/callback — Microsoft redirects here with ?code=...&state=..."""
    if not SSO_ENABLED:
        return jsonify({'error': 'SSO is not enabled'}), 404
    if not _sso_deps_ok():
        return _ui_sso_fail('SSO dependencies missing on the server')

    error = request.args.get('error')
    if error:
        return _ui_sso_fail(f'Microsoft returned an error: {error} '
                            f'{request.args.get("error_description", "")}')

    oauth = _sso_read_oauth_state()
    state = request.args.get('state', '')
    if not oauth or not state or oauth.get('state') != state:
        return _ui_sso_fail('state mismatch (possible CSRF) — please retry')

    code = request.args.get('code', '')
    if not code:
        return _ui_sso_fail('missing authorization code — please retry')

    try:
        tokens = _sso_exchange_code(code, oauth.get('code_verifier', ''))
    except Exception as exc:
        logger.error("SSO token exchange failed: %s", exc)
        return _ui_sso_fail('token exchange failed — please retry')

    id_token = tokens.get('id_token')
    if not id_token:
        return _ui_sso_fail('no ID token returned — please retry')

    try:
        claims = _sso_validate_id_token(id_token, oauth.get('nonce', ''))
    except jwt.InvalidTokenError as exc:
        logger.warning("SSO ID token rejected: %s", exc)
        return _ui_sso_fail('token validation failed — please retry')

    allowed, reason = _sso_user_allowed(claims)
    if not allowed:
        logger.info("SSO login denied for %s: %s",
                    claims.get('preferred_username'), reason)
        return _ui_sso_fail(f'not authorized to sign in ({reason})')

    username = str(
        claims.get('preferred_username') or claims.get('upn')
        or claims.get('email') or claims.get('sub')
    )
    resp = redirect('/')
    resp.set_cookie(
        'taxii2_ui_session', _session_cookie(username),
        max_age=_ui_session_ttl, httponly=True, samesite='Lax',
    )
    resp.delete_cookie(_oauth_state_cookie)
    logger.info("SSO login successful for %s", username)
    return resp


def _ui_sso_fail(message: str) -> Response:
    """Render a small inline error and point back at the login form."""
    resp = make_response(
        f'<!doctype html><meta charset="utf-8">'
        f'<title>Sign-in failed</title><body style="font-family:system-ui;max-width:520px;'
        f'margin:80px auto;padding:0 16px"><h2>Sign-in failed</h2>'
        f'<p>{message}</p><p><a href="/">Return to login</a></p></body>',
        401,
    )
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    return resp


def sso_public_info() -> Dict[str, Any]:
    """Small payload for the UI to decide whether to show the SSO button."""
    return {
        'enabled': SSO_ENABLED,
        'provider': 'Microsoft Entra ID',
    }


# ---------------------------------------------------------------------------
# TAXII 2 Response Generation
# ---------------------------------------------------------------------------

def _append_elements(parent: ET.Element, data: Any, tag: str) -> ET.Element:
    """Recursively render a (possibly nested) dict/list/scalar as XML elements.

    None values are skipped. Element text is escaped automatically by ElementTree.
    """
    elem = ET.SubElement(parent, tag)
    if isinstance(data, dict):
        for key, value in data.items():
            if value is None:
                continue
            _append_elements(elem, value, str(key))
    elif isinstance(data, (list, tuple)):
        for value in data:
            if value is None:
                continue
            _append_elements(elem, value, 'item')
    else:
        elem.text = str(data)
    return elem


def generate_taxii_bundle(bundles: List[Dict[str, Any]]) -> str:
    """Generate TAXII 2 bundle XML for the given STIX object descriptors.

    Each bundle item: {"id": ..., "type": ..., "object": {...}}.
    """
    bundle_id = str((CONFIG.get('taxii', {}) or {}).get('bundle_id') or 'Bundle-1')
    if '{timestamp}' in bundle_id:
        bundle_id = bundle_id.replace('{timestamp}', str(int(time.time())))

    root = ET.Element(
        'Response',
        {
            'xmlns': 'stix-taxon',
            'xmlns:v2_1': 'http://cyclonedx.org/schema/cyclonedx/1.3',
        },
    )
    body = ET.SubElement(root, 'body')
    v2_1 = ET.SubElement(body, 'v2_1')
    bundle = ET.SubElement(v2_1, 'bundle', {'id': bundle_id})
    objects_el = ET.SubElement(bundle, 'objects')

    for item in bundles:
        obj_el = ET.SubElement(
            objects_el,
            'object',
            {'id': str(item.get('id', '')), 'type': str(item.get('type', ''))},
        )
        obj = item.get('object')
        if obj:
            _append_elements(obj_el, obj, 'properties')

    return ET.tostring(root, encoding='utf-8').decode('utf-8')


def _unauthorized_feed_response() -> Response:
    """401 response in the same XML envelope as the feed."""
    root = ET.Element(
        'Response',
        {
            'xmlns': 'stix-taxon',
            'xmlns:v2_1': 'http://cyclonedx.org/schema/cyclonedx/1.3',
        },
    )
    body = ET.SubElement(root, 'body')
    error = ET.SubElement(body, 'error')
    error.text = 'Unauthorized'
    return Response(
        ET.tostring(root, encoding='utf-8').decode('utf-8'),
        mimetype='application/xml; charset=utf-8',
        status=401,
    )


# ---------------------------------------------------------------------------
# Feed Ingestion (shared by REST endpoint and pollers)
# ---------------------------------------------------------------------------

def _extract_object_fields(
    obj_type: str, object_dict: Any
) -> Dict[str, Optional[str]]:
    """Extract typed values from an ingested STIX object payload.

    Accepts both flat ({"value": ...}) and type-nested
    ({"ipv4-addr": {"value": ...}}) payload shapes.
    """
    if not isinstance(object_dict, dict):
        object_dict = {}
    nested = object_dict.get(obj_type)
    inner = nested if isinstance(nested, dict) else object_dict

    result: Dict[str, Optional[str]] = {
        'name': None,
        'hash_value': None,
        'ip_address': None,
        'domain': None,
    }

    if obj_type == 'file-hash':
        hv = inner.get('hash_value', object_dict.get('hash_value'))
        if isinstance(hv, dict):
            result['hash_value'] = hv.get('value')
        elif isinstance(hv, str):
            result['hash_value'] = hv
    elif obj_type == 'ipv4-addr':
        result['ip_address'] = inner.get('value')
    elif obj_type == 'domain-name':
        result['domain'] = inner.get('value')
    elif obj_type in ('indicator', 'malware', 'malware-family'):
        result['name'] = inner.get('value') or inner.get('name')
    return result


def ingest_objects(stix_objects: List[Dict[str, Any]], mode: str = 'replace',
                   source: str = 'manual') -> int:
    """Store STIX objects into the feed (memory + DB).

    ``mode``:
      * ``'replace'`` (default, used by the web UI / manual ingest) — the
        entire *manual* feed is wiped and rebuilt from ``stix_objects``.
        Objects pulled from external communities (``source != 'manual'``,
        e.g. the OTX puller) are left untouched.
      * ``'merge'`` (used by community pollers) — upsert by STIX id: new
        objects are added, existing ones get refreshed (labels/confidence/
        last_seen). Manual intel is never touched, and objects are only ever
        appended, never dropped by a poller.

    ``source`` tags each stored object with its origin (``'manual'`` for
    web-UI/API ingest, ``'otx'`` for the OTX puller, ...).

    Returns the number of objects stored in the mode-specific batch.
    Raises on failure.
    """
    session = create_session()
    try:
        with memory_lock:
            now = datetime.utcnow()
            batch_ids = [o.get('id') for o in stix_objects if o.get('id')]
            if mode == 'merge':
                # Upsert: keep manual and other-source rows, update matching ids.
                preserved_revoked = {}
                if batch_ids:
                    existing = {
                        row.stix_id: row
                        for row in session.query(STIXObject).filter(
                            STIXObject.stix_id.in_(batch_ids)
                        ).all()
                    }
                else:
                    existing = {}
            else:
                # Replace: wipe only the manual feed; community-sourced rows
                # survive so a UI save cannot delete pulled intel.
                preserved_revoked = {
                    r.stix_id: bool(r.revoked)
                    for r in session.query(STIXObject.stix_id, STIXObject.revoked).filter_by(
                        source=source
                    ).all()
                }
                session.query(STIXObject).filter_by(source=source).delete()
                for s in [s for s in memory_store if memory_store[s].source == source]:
                    memory_store.pop(s, None)
                session.flush()
                existing = {}

            count = 0
            for obj_dict in stix_objects:
                stix_id = obj_dict.get('id')
                obj_type = obj_dict.get('type')
                if not stix_id or not obj_type:
                    continue

                object_dict = obj_dict.get('object') or {}
                labels = obj_dict.get('labels') or []
                if not isinstance(labels, list):
                    labels = [labels]
                confidence = int(obj_dict.get('confidence', 0) or 0)
                fields = _extract_object_fields(obj_type, object_dict)

                existing_row = existing.get(stix_id)
                # Revocation is sticky. An explicit "revoked" in the payload
                # wins; otherwise a previously-revoked object (merge: its
                # existing row, replace: captured before the delete) stays
                # revoked. Only the revoke endpoint (action=unrevoke) can
                # reinstate an object.
                _raw_revoked = (
                    obj_dict.get('revoked', object_dict.get('revoked'))
                )
                if _raw_revoked is None:
                    if existing_row is not None:
                        revoked = bool(existing_row.revoked)
                    else:
                        revoked = preserved_revoked.get(stix_id, False)
                else:
                    revoked = bool(_raw_revoked)

                memory_store[stix_id] = ThreatIntel(
                    stix_id=stix_id,
                    object_type=obj_type,
                    labels=labels,
                    confidence=confidence,
                    name=obj_dict.get('name') or fields['name'],
                    description=obj_dict.get('description'),
                    hash_value=fields['hash_value'],
                    ip_address=fields['ip_address'],
                    domain=fields['domain'],
                    source=source,
                    revoked=revoked,
                )

                row = existing.get(stix_id)
                if row is not None and mode == 'merge':
                    # Refresh in place; keep first_seen and origin.
                    row.object_type = obj_type
                    row.name = obj_dict.get('name') or fields['name']
                    row.labels = ','.join(str(l) for l in labels)
                    row.confidence = confidence
                    row.hash_value = fields['hash_value']
                    row.ip_address = fields['ip_address']
                    row.domain = fields['domain']
                    row.last_seen = now
                    row.revoked = revoked  # sticky (see above); keeps first revoked_at
                else:
                    row = STIXObject(
                        id=stix_id,
                        stix_id=stix_id,
                        object_type=obj_type,
                        name=obj_dict.get('name') or fields['name'],
                        description=obj_dict.get('description'),
                        labels=','.join(str(l) for l in labels),
                        confidence=confidence,
                        hash_value=fields['hash_value'],
                        ip_address=fields['ip_address'],
                        domain=fields['domain'],
                        source=source,
                        first_seen=now,
                        last_seen=now,
                        revoked=revoked,
                        revoked_at=now if revoked else None,
                    )
                    existing[stix_id] = row
                    session.add(row)
                count += 1

            session.commit()
            return count
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def purge_all() -> None:
    """Purge all threat intelligence data (memory + DB)."""
    session = create_session()
    try:
        with memory_lock:
            memory_store.clear()
            session.query(STIXObject).delete()
            session.commit()
    finally:
        session.close()


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# TAXII 2.1 (OASIS) Server — Vision One / TAXII client compatible
# ---------------------------------------------------------------------------
# Trend Micro Vision One is a TAXII 2.1 *client* (it polls e.g. AlienVault OTX,
# which is a TAXII 2.1 server). This section exposes a standards-compliant
# TAXII 2.1 API root, one collection of STIX 2.1 JSON objects, and a
# subscriptions stub — the same surface Vision One polls from OTX.

TAXII_CFG = CONFIG.get('taxii', {}) or {}
TAXII_COLLECTION_ID = str(TAXII_CFG.get('collection_id') or 'threat-intel')
TAXII_COLLECTION_TITLE = str(
    TAXII_CFG.get('collection_title') or 'Custom Threat Intelligence Feed'
)


def _stix_now() -> str:
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')


_HASH_KEY_BY_ALGO = {
    'md5': 'MD5', 'sha1': 'SHA-1', 'sha256': 'SHA-256', 'sha512': 'SHA-512',
}


def threat_intel_to_stix21(obj: ThreatIntel) -> Optional[Dict[str, Any]]:
    """Render a stored object as a standard STIX 2.1 object (JSON-able)."""
    now = _stix_now()
    common = {
        'spec_version': '2.1',
        'created': now,
        'modified': now,
        'revoked': bool(obj.revoked),
    }

    if obj.object_type == 'ipv4-addr' and obj.ip_address:
        return {
            **common,
            'type': 'ipv4-addr',
            'id': f"ipv4-addr--{obj.ip_address.replace('.', '-')}",
            'value': obj.ip_address,
            'labels': obj.labels or [],
            'confidence': obj.confidence or 0,
        }

    if obj.object_type == 'domain-name' and obj.domain:
        return {
            **common,
            'type': 'domain-name',
            'id': f"domain-name--{obj.domain.replace('.', '-')}",
            'value': obj.domain,
            'labels': obj.labels or [],
            'confidence': obj.confidence or 0,
        }

    if obj.object_type == 'file-hash' and obj.hash_value:
        algo = (obj.labels[0] if obj.labels else 'sha256').lower()
        return {
            **common,
            'type': 'file',
            'id': 'file--' + uuid.uuid5(uuid.NAMESPACE_OID, obj.hash_value).hex,
            'hashes': {_HASH_KEY_BY_ALGO.get(algo, 'SHA-256'): obj.hash_value},
            'labels': obj.labels or [],
            'confidence': obj.confidence or 0,
        }

    # indicator / malware / free-text: emit an STIX indicator with a pattern
    # derived from the value when its kind is recognizable.
    value = obj.name or obj.ip_address or obj.domain or obj.hash_value or ''
    if not value:
        return None
    guessed, algo = _guess_object_type(value)
    if guessed == 'ipv4-addr':
        pattern = f"[ipv4-addr:value = '{value}']"
    elif guessed == 'domain-name':
        pattern = f"[domain-name:value = '{value}']"
    elif guessed == 'file-hash':
        key = _HASH_KEY_BY_ALGO.get(algo or 'sha256', 'SHA-256')
        pattern = f"[file:hashes.'{key}' = '{value}']"
    else:
        # Unrecognizable free text: community extension type (x- prefix is
        # spec-legal); TAXII clients that only want typed indicators skip it.
        return {
            **common,
            'type': 'x-ti-indicator',
            'id': 'x-ti-indicator--' + uuid.uuid5(uuid.NAMESPACE_OID, value).hex,
            'value': value,
            'labels': obj.labels or [],
            'confidence': obj.confidence or 0,
        }

    return {
        **common,
        'type': 'indicator',
        'id': 'indicator--' + uuid.uuid5(uuid.NAMESPACE_OID, pattern).hex,
        'pattern': pattern,
        'pattern_type': 'stix',
        'pattern_version': '2.1',
        'valid_from': now,
        'labels': obj.labels or [],
        'confidence': obj.confidence or 0,
    }


# ---------------------------------------------------------------------------
# Community-intel gate (the filter between this server and Vision One)
# ---------------------------------------------------------------------------
# Sits in front of the /taxii2/ collection Vision One polls. It only gates
# objects pulled from external communities (source != 'manual', e.g. the OTX
# puller); hand-fed intel passes untouched. The gate is read-time: every
# object stays stored in the DB — it only decides what Vision One is served,
# so it is fully auditable and reversible.

FILTER_CFG = (CONFIG.get('intel_filter', {}) or {})
# By default EVERY source except 'manual' is gated (OTX pulls, third-party
# TAXII pulls, ...). If community_sources is explicitly set (non-empty),
# only those sources are gated and other non-manual sources are served.
FILTER_COMMUNITY_SOURCES = tuple(
    (FILTER_CFG.get('community_sources') or [])
)
FILTER_DROP_PRIVATE_IPS = bool(FILTER_CFG.get('drop_private_ips', True))
FILTER_BLOCKLIST = {
    str(v).strip().lower()
    for v in (FILTER_CFG.get('blocklist') or [])
    if str(v).strip()
}
FILTER_FRESHNESS_DAYS = FILTER_CFG.get('freshness_days')
_FILTER_MIN_CONFIDENCE = FILTER_CFG.get('min_confidence')


def _is_private_or_reserved_ip(value: str) -> bool:
    """True for non-routable / special-use IPv4 addresses.

    Covers private (10/8, 172.16/12, 192.168/16), loopback (127/8),
    link-local (169.254/16), "this network" (0/8), IPv4-mapped IPv6
    (::ffff:10.0.0.1), carrier-grade NAT, and the rest of the IANA
    special-purpose registry (private, loopback, link-local, reserved,
    benchmarking, ...). These dominate OTX honeypot feeds and are the
    main source of false positives.
    """
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if not ip.is_global:
        return True
    # A handful of global ranges we still treat as noise:
    if ip.is_reserved:
        return True
    # 240.0.0.0/4 (240.x–255.x) is reserved for future use.
    if ip.version == 4 and 240 <= int(str(ip).split('.')[0], 10) <= 255:
        return True
    return False


def community_intel_reason(obj: ThreatIntel, row: 'STIXObject') -> Optional[str]:
    """Return the reason a *community-sourced* object is withheld, or None
    to serve it.

    Called only for objects whose ``source`` is in
    ``FILTER_COMMUNITY_SOURCES`` (see ``build_stix_bundle``). Manual intel
    is never passed here.
    """
    # 1) Explicit blocklist (exact value match).
    for value in (obj.ip_address, obj.domain, obj.hash_value, obj.name):
        if value and value.lower() in FILTER_BLOCKLIST:
            return 'blocklist'

    # 2) Private / reserved IPs (honors the drop_private_ips toggle).
    if FILTER_DROP_PRIVATE_IPS and obj.ip_address and _is_private_or_reserved_ip(obj.ip_address):
        return 'private-ip'

    # 3) Confidence floor.
    if _FILTER_MIN_CONFIDENCE is not None:
        try:
            if (obj.confidence or 0) < int(_FILTER_MIN_CONFIDENCE):
                return 'low-confidence'
        except (TypeError, ValueError):
            pass

    # 4) Freshness window (last seen / modified older than N days).
    if FILTER_FRESHNESS_DAYS is not None:
        try:
            days = int(FILTER_FRESHNESS_DAYS)
        except (TypeError, ValueError):
            days = None
        if days is not None:
            anchor = row.last_seen or row.modified or None
            if anchor is not None:
                # Stored as naive UTC (datetime.utcnow); compare consistently.
                if (datetime.utcnow() - anchor) > timedelta(days=days):
                    return 'stale'
    return None


_GATE_REASON_LABELS = {
    'blocklist': 'Blocklisted',
    'private-ip': 'Private / reserved IP',
    'low-confidence': 'Low confidence',
    'stale': 'Stale (older than freshness window)',
}


def _source_is_gated(src: Optional[str]) -> bool:
    """True if intel from ``src`` passes through the intel gate.

    Manual intel is never gated. When ``intel_filter.community_sources`` is
    set (non-empty) only those sources are gated; otherwise every non-manual
    source is gated (default — OTX, third-party TAXII pulls, ...).
    """
    src = src or 'manual'
    if src == 'manual':
        return False
    if FILTER_COMMUNITY_SOURCES:
        return src in FILTER_COMMUNITY_SOURCES
    return True


def gate_verdict(obj: ThreatIntel, row: 'STIXObject') -> Dict[str, Any]:
    """Return the intel-gate verdict for a stored object.

    Shared by ``build_stix_bundle`` (decides what Vision One is served) and
    ``list_objects`` (lets the web UI show what is withheld, and why).

    Returns::

        {'source': 'manual'|'otx'|...,   # object origin
         'gated': bool,                    # withheld from the Vision One feed?
         'reason': str|None,               # machine reason or None
         'reason_label': str}              # human-readable reason ('' if served)

    Manual intel is never gated (``gated`` False).
    """
    src = obj.source or 'manual'
    if not _source_is_gated(src):
        return {'source': src, 'gated': False, 'reason': None, 'reason_label': ''}
    reason = community_intel_reason(obj, row)
    if reason is None:
        return {'source': src, 'gated': False, 'reason': None, 'reason_label': ''}
    return {
        'source': src,
        'gated': True,
        'reason': reason,
        'reason_label': _GATE_REASON_LABELS.get(reason, reason),
    }


def build_stix_bundle(since: Optional[str] = None,
                      match_types: Optional[List[str]] = None,
                      match_ids: Optional[List[str]] = None,
                      added_after: Optional[str] = None) -> Dict[str, Any]:
    """Build a STIX 2.1 bundle of the current feed (optionally filtered).

    TAXII 2.1 Get Objects parameters:
      * ``since`` / ``added_after``: only objects modified after this
        ISO-8601 timestamp (``added_after`` is the spec name; ``since`` is
        accepted for back-compat).
      * ``match_types``: ``match[type]`` - only these STIX object types.
      * ``match_ids``: ``match[id]`` - only these exact object ids.

    Revoked objects are INCLUDED but rendered with ``revoked: true`` (clients
    purge them); they are never silently dropped."""
    session = create_session()
    try:
        q = session.query(STIXObject)
        cutoff = since or added_after
        if cutoff:
            try:
                cutoff_dt = datetime.fromisoformat(cutoff.replace('Z', ''))
                q = q.filter(STIXObject.modified >= cutoff_dt)
            except ValueError:
                pass
        if match_ids:
            q = q.filter(STIXObject.stix_id.in_(match_ids))
        rows = q.all()
    finally:
        session.close()

    type_filter = ({str(t) for t in match_types} if match_types else None)

    objects: List[Dict[str, Any]] = []
    withheld = 0
    with memory_lock:
        for row in rows:
            obj = memory_store.get(row.stix_id)
            if obj is None:
                continue
            # match[type] - filter on the stored type we would render.
            if type_filter is not None and row.object_type not in type_filter:
                continue
            # Community-intel gate (manual intel is never gated).
            verdict = gate_verdict(obj, row)
            if verdict['gated']:
                withheld += 1
                continue
            stix = threat_intel_to_stix21(obj)
            if stix is not None:
                objects.append(stix)

    if withheld:
        logger.info(
            "Intel gate withheld %s community object(s) from the TAXII feed",
            withheld,
        )

    return {
        'type': 'bundle',
        'id': 'bundle--' + uuid.uuid4().hex,
        'spec_version': '2.1',
        'objects': objects,
    }


def _taxii_message(collection: Optional[str] = None,
                   content: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    msg: Dict[str, Any] = {'object': 'message', 'meta': {'timestamp': _stix_now()}}
    if collection:
        msg['meta']['collection'] = collection
    if content is not None:
        msg['content'] = {
            'object': 'content',
            'id': uuid.uuid4().hex,
            'content_type': 'application/stix+json',
            'content': content,
        }
    return msg


def _taxii_response(payload: Dict[str, Any], status: int = 200) -> Response:
    return Response(
        json.dumps(payload),
        status=status,
        mimetype='application/taxii+json;version=2.1',
        headers={'TAXII-ServiceVersion': '2.1'},
    )


def _taxii_unauthorized() -> Response:
    return Response(
        json.dumps({
            'status_code': '401',
            'title': 'Unauthorized',
            'detail': 'TAXII client authentication failed.',
            'errors': {'code': 'basic_auth'},
        }),
        status=401,
        mimetype='application/taxii+json;version=2.1',
        headers={
            'WWW-Authenticate': 'Basic realm="taxii"',
            'TAXII-ServiceVersion': '2.1',
        },
    )


def _taxii_check_auth() -> bool:
    """Accept HTTP Basic auth (TAXII standard) or the X-Taxii-* headers."""
    user, pw = _request_taxii_credentials()
    return _validate_taxii_auth(user, pw)


def _taxii_base_url() -> str:
    return request.url_root.rstrip('/') + '/taxii2/'


def _collection_url(base_url: str, collection_id: str) -> str:
    return f'{base_url}collections/{collection_id}/'


def _collection_resource(base_url: str, collection_id: str) -> Dict[str, Any]:
    """A single Collection Resource (flat — fields at top level per spec 5.2.1)."""
    return {
        'id': collection_id,
        'title': TAXII_COLLECTION_TITLE,
        'description': (
            'Custom threat intelligence objects: IPv4 addresses, domain names, '
            'file hashes, and indicators.'
        ),
        'can_read': True,
        'can_write': False,
        'version': '2.1',
        'created': _stix_now(),
        'meta': {'collection_url': _collection_url(base_url, collection_id)},
    }


def _last_status() -> Dict[str, Any]:
    now = _stix_now()
    return {
        'id': 'last',
        'status': 'complete',
        'request_timestamp': now,
        'completion_timestamp': now,
        'total_count': 0,
        'success_count': 0,
        'failure_count': 0,
        'pending_count': 0,
        'successes': [],
        'failures': [],
        'pendings': [],
    }


@app.route('/taxii2', methods=['GET'])
@app.route('/taxii2/', methods=['GET'])
@app.route('/taxii2/api-root', methods=['GET'])
@app.route('/taxii2/api-root/', methods=['GET'])
def taxii_api_root():
    """TAXII 2.1 API Root (section 4.2) + Server Discovery (section 4.1).

    Serves as the single canonical URL a TAXII client (e.g. Vision One) is
    configured with:  http://<server>:5000/taxii2

    The resource carries both the API-root fields (``versions``) and the
    discovery field (``api_roots``) so that both ``Server(url)`` (full
    discovery) and ``ApiRoot(url)`` (direct) client flows succeed.
    """
    if not _taxii_check_auth():
        return _taxii_unauthorized()
    base = _taxii_base_url()
    return _taxii_response({
        'object': 'taxii-api-root',
        'title': 'TAXII 2.1 Threat Intelligence Server',
        'description': 'Custom STIX 2.1 threat intelligence feed.',
        'contact': {'name': 'TAXII Server Administrator'},
        'versions': ['2.1'],
        'max_content_length': 104857600,
        'api_roots': [base],
        'default': base,
        'meta': {'api_root_url': base, 'status': 'enabled'},
        'endpoints': {
            'collections': base + 'collections/',
            'objects': base + 'collections/{collection}/objects/',
            'status': base + 'status/',
        },
    })


@app.route('/taxii2/collections', methods=['GET'])
@app.route('/taxii2/collections/', methods=['GET'])
def taxii_collections():
    """TAXII 2.1 Get Collections (section 5.1)."""
    if not _taxii_check_auth():
        return _taxii_unauthorized()
    base = _taxii_base_url()
    return _taxii_response({
        'object': 'collections',
        'meta': {'count': 1, 'first': 0, 'last': 0},
        'collections': [_collection_resource(base, TAXII_COLLECTION_ID)],
    })


@app.route('/taxii2/collections/<collection_id>', methods=['GET'])
@app.route('/taxii2/collections/<collection_id>/', methods=['GET'])
def taxii_collection_info(collection_id: str):
    """TAXII 2.1 Get a Collection (section 5.2)."""
    if collection_id != TAXII_COLLECTION_ID:
        return _taxii_response({
            'status_code': '404', 'title': 'Not Found',
            'detail': f'Collection {collection_id} not found.',
        }, 404)
    if not _taxii_check_auth():
        return _taxii_unauthorized()
    base = _taxii_base_url()
    info = _collection_resource(base, collection_id)
    info['url'] = _collection_url(base, collection_id)
    return _taxii_response(info)


@app.route('/taxii2/collections/<collection_id>/objects', methods=['GET', 'POST'])
@app.route('/taxii2/collections/<collection_id>/objects/', methods=['GET', 'POST'])
def taxii_objects(collection_id: str):
    """TAXII 2.1 Get Objects (5.3) / Add Objects (5.4) for a collection."""
    if collection_id != TAXII_COLLECTION_ID:
        return _taxii_response({
            'status_code': '404', 'title': 'Not Found',
            'detail': f'Collection {collection_id} not found.',
        }, 404)
    if not _taxii_check_auth():
        return _taxii_unauthorized()

    if request.method == 'POST':
        # Add Objects: this is a read-only feed; acknowledge as a no-op.
        return _taxii_response(_last_status())

    # TAXII 2.1 Get Objects query parameters (section 5.3):
    #   since / added_after  -> only objects modified after the timestamp
    #   match[type]          -> only these STIX object types
    #   match[id]            -> only these exact object ids
    # (?since= kept as an accepted alias of added_after.)
    since = request.args.get('since') or request.args.get('added_after')
    match_types = [t for t in request.args.getlist('match[type]') if t]
    match_ids = [i for i in request.args.getlist('match[id]') if i]
    bundle = build_stix_bundle(
        since=since, match_types=match_types, match_ids=match_ids
    )
    return _taxii_response(_taxii_message(collection_id, bundle))


@app.route('/taxii2/status/<status_id>', methods=['GET'])
@app.route('/taxii2/status/<status_id>/', methods=['GET'])
def taxii_status(status_id: str):
    """TAXII 2.1 Status (section 5.7) — read-only feed reports complete."""
    if not _taxii_check_auth():
        return _taxii_unauthorized()
    return _taxii_response(_last_status())


@app.route('/taxii2/subscriptions/', methods=['GET'])
def taxii_subscriptions():
    """TAXII 2.1 subscription list (empty — clients poll the collection)."""
    if not _taxii_check_auth():
        return _taxii_unauthorized()
    return _taxii_response({
        'object': 'subscriptions',
        'meta': {'count': 0, 'first': 0, 'last': 0},
        'subscriptions': [],
    })


@app.route('/feed', methods=['GET'])
def get_feed():
    """GET /feed — latest STIX feed in TAXII 2 XML format (authenticated)."""
    if not _request_allowed():
        return _unauthorized_feed_response()

    session = create_session()
    try:
        db_objects = session.query(STIXObject).all()
    finally:
        session.close()

    with memory_lock:
        bundles = [
            {
                'id': obj.stix_id,
                'type': obj.object_type,
                'object': memory_store[obj.stix_id].to_stix_object().get('object', {}),
            }
            for obj in db_objects
            if obj.stix_id in memory_store
        ]

    return Response(
        generate_taxii_bundle(bundles),
        mimetype='application/xml; charset=utf-8',
        status=200,
    )


@app.route('/objects', methods=['GET'])
def list_objects():
    """GET /objects — JSON view of current feed objects (same auth as /feed).

    Used by the web UI (and handy for scripting): lists what is currently
    in the feed so entries can be reviewed before re-ingesting.
    """
    if not _request_allowed():
        return jsonify({'error': 'Unauthorized'}), 401

    session = create_session()
    try:
        db_objects = session.query(STIXObject).all()
    finally:
        session.close()

    with memory_lock:
        objects = []
        for row in db_objects:
            if row.stix_id not in memory_store:
                continue
            obj = memory_store[row.stix_id]
            verdict = gate_verdict(obj, row)
            objects.append({
                'id': row.stix_id,
                'type': row.object_type,
                'value': (
                    obj.ip_address
                    or obj.domain
                    or obj.hash_value
                    or obj.name
                ),
                'labels': obj.labels or [],
                'confidence': row.confidence,
                'source': verdict['source'],
                'gated': verdict['gated'],
                'gate_reason': verdict['reason'],
                'gate_reason_label': verdict['reason_label'],
                'revoked': bool(row.revoked),
                'revoked_at': row.revoked_at.isoformat() + 'Z' if row.revoked_at else None,
                'last_seen': row.last_seen.isoformat() + 'Z' if row.last_seen else None,
            })

    withheld_count = sum(1 for o in objects if o['gated'])
    return jsonify({
        'objects': objects,
        'count': len(objects),
        'served_count': len(objects) - withheld_count,
        'withheld_count': withheld_count,
    }), 200


@app.route('/objects/<stix_id>/revoke', methods=['POST'])
def revoke_object(stix_id: str):
    """POST /objects/<stix_id>/revoke — revoke or reinstate an object.

    Body: {"action": "revoke"} (default) or {"action": "unrevoke"}. Revoking
    sets STIX ``revoked: true`` (still served, so clients drop it); unrevoking
    reinstates it. Revocation is the manual side of the indicator lifecycle.
    """
    if not _request_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    action = str(data.get('action', 'revoke') or 'revoke').lower()
    if action not in ('revoke', 'unrevoke'):
        return jsonify({'error': 'action must be "revoke" or "unrevoke"'}), 400

    session = create_session()
    try:
        row = session.query(STIXObject).filter_by(stix_id=stix_id).first()
        if row is None:
            return jsonify({'error': f'Object not found: {stix_id}'}), 404
        now = datetime.utcnow()
        if action == 'revoke':
            if row.revoked:
                return jsonify({'id': stix_id, 'revoked': True, 'changed': False})
            row.revoked = True
            row.revoked_at = now
        else:
            if not row.revoked:
                return jsonify({'id': stix_id, 'revoked': False, 'changed': False})
            row.revoked = False
            row.revoked_at = None
        session.commit()
        with memory_lock:
            obj = memory_store.get(stix_id)
            if obj is not None:
                obj.revoked = bool(row.revoked)
        logger.info(
            "Object %s %s via %s (source=%s)",
            stix_id, action, request.remote_addr, row.source,
        )
        return jsonify({'id': stix_id, 'revoked': bool(row.revoked), 'changed': True})
    except Exception as exc:
        session.rollback()
        logger.error("Revoke error: %s", exc)
        return jsonify({'error': str(exc)}), 500
    finally:
        session.close()


@app.route('/ui', methods=['GET'])
@app.route('/', methods=['GET'])
def web_ui():
    """GET / or /ui — simple web form for feeding intel (no curl needed)."""
    return send_from_directory(
        str(Path(__file__).parent), 'intel-ui.html'
    )


@app.route('/feed/ingest', methods=['POST'])
def ingest_data():
    """POST /feed/ingest — accept STIX 2.1 JSON objects, replace the feed."""
    if not _request_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json(silent=True)
    if not data or not data.get('stix_objects'):
        return jsonify({'error': 'No valid data provided'}), 400

    stix_objects = data.get('stix_objects')
    if not isinstance(stix_objects, list):
        return jsonify({'error': 'stix_objects must be a list'}), 400

    try:
        count = ingest_objects(stix_objects)
    except Exception as exc:
        logger.error("Ingest error: %s", exc)
        return jsonify({'error': str(exc)}), 500

    return jsonify({'message': 'Data ingested successfully', 'objects_count': count}), 200


@app.route('/feed/purge', methods=['DELETE'])
def purge_data():
    """DELETE /feed/purge — purge all threat intelligence data."""
    if not _request_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        purge_all()
    except Exception as exc:
        logger.error("Purge error: %s", exc)
        return jsonify({'error': str(exc)}), 500
    return jsonify({'message': 'All data purged successfully'}), 200


@app.route('/auth', methods=['POST'])
def authenticate():
    """POST /auth — authenticate a client against its stored subscription."""
    data = request.form.to_dict()
    username = data.get('username', '')
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 401

    session = create_session()
    try:
        subscription = (
            session.query(Subscription).filter_by(client_id=username).first()
        )
        if (
            not subscription
            or not subscription.password_hash
            or not check_password_hash(subscription.password_hash, password)
        ):
            return jsonify({'error': 'Invalid credentials'}), 401

        subscription.last_verified = datetime.utcnow()
        session.commit()
        return (
            jsonify(
                {
                    'authenticated': True,
                    'client_id': username,
                    'subscription_id': subscription.id,
                }
            ),
            200,
        )
    finally:
        session.close()


@app.route('/subscriptions', methods=['GET'])
def list_subscriptions():
    """GET /subscriptions — list all subscriptions."""
    session = create_session()
    try:
        subs = session.query(Subscription).all()
        result = [
            {
                'client_id': s.client_id,
                'id': s.id,
                'enabled': s.enabled,
                'created': s.created.isoformat() if s.created else None,
                'last_verified': s.last_verified.isoformat() if s.last_verified else None,
            }
            for s in subs
        ]
    finally:
        session.close()
    return jsonify(result), 200


@app.route('/subscriptions/<client_id>', methods=['POST'])
def add_subscription(client_id: str):
    """POST /subscriptions/<client_id> — create (or update) a subscription."""
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')
    if not password:
        return jsonify({'error': 'Password required'}), 400

    session = create_session()
    try:
        sub = session.query(Subscription).filter_by(client_id=client_id).first()
        if sub:
            sub.password_hash = generate_password_hash(password)
            updated = True
        else:
            sub = Subscription(
                id=f"{client_id}@{uuid.uuid4().hex[:8]}",
                client_id=client_id,
                password_hash=generate_password_hash(password),
            )
            session.add(sub)
            updated = False
        session.commit()
        return (
            jsonify(
                {
                    'message': 'Subscription updated' if updated else 'Subscription created',
                    'client_id': client_id,
                    'id': sub.id,
                }
            ),
            200 if updated else 201,
        )
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Web UI session + community-source (puller) endpoints
# ---------------------------------------------------------------------------

@app.route('/ui/session', methods=['GET'])
def ui_session():
    """GET /ui/session — report whether the current cookie is a valid login."""
    user = _session_user()
    return jsonify({
        'authenticated': user is not None,
        'user': user or None,
        'sso': sso_public_info(),
    }), 200


@app.route('/ui/login', methods=['POST'])
def ui_login():
    """POST /ui/login — authenticate to the dashboard, set a session cookie."""
    data = request.get_json(silent=True) or {}
    username = str(data.get('username') or '')
    password = str(data.get('password') or '')
    if username != _ui_username or password != _ui_password:
        return jsonify({'error': 'Invalid credentials'}), 401
    resp = jsonify({'message': 'Logged in', 'user': username})
    resp.set_cookie(
        'taxii2_ui_session',
        _session_cookie(username),
        max_age=_ui_session_ttl,
        httponly=True,
        samesite='Lax',
    )
    return resp, 200


@app.route('/ui/logout', methods=['POST'])
def ui_logout():
    """POST /ui/logout — clear the dashboard session cookie."""
    resp = jsonify({'message': 'Logged out'})
    resp.delete_cookie('taxii2_ui_session')
    return resp, 200


@app.route('/community/pullers', methods=['GET'])
def community_pullers():
    """GET /community/pullers — status of all community sources (dashboard)."""
    if not _request_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({
        'pullers': [otx_poller.status()] + [p.status() for p in taxii_pullers],
    }), 200


@app.route('/community/pull/<name>', methods=['POST'])
def community_pull(name: str):
    """POST /community/pull/<name> — run one pull cycle now ('Pull now')."""
    if not _request_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    if name == 'otx':
        puller = otx_poller
    else:
        puller = next((p for p in taxii_pullers if p.name == name), None)
    if puller is None:
        return jsonify({'error': f'Unknown puller: {name}'}), 404
    result = puller.pull_now()
    if result.get('error') and 'misconfigured' in result['error']:
        return jsonify(result), 400
    return jsonify(result), 200


@app.route('/health', methods=['GET'])
def health_check():
    """GET /health — health check endpoint for monitoring."""
    db_status = 'connected'
    session = create_session()
    try:
        session.execute(text('SELECT 1'))
    except Exception:  # pragma: no cover - depends on DB availability
        db_status = 'error'
    finally:
        session.close()

    with memory_lock:
        objects_count = len(memory_store)

    return (
        jsonify(
            {
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),
                'objects_count': objects_count,
                'database': db_status,
                'poller': {
                    'otx': _poller_state(otx_poller),
                    'self_check': _poller_state(self_check_poller),
                    'taxii': {p.name: _poller_state(p) for p in taxii_pullers},
                },
            }
        ),
        200,
    )


def _poller_state(poller: Any) -> str:
    thread = getattr(poller, '_thread', None)
    return 'running' if thread is not None and thread.is_alive() else 'stopped'


# ---------------------------------------------------------------------------
# Pollers
# ---------------------------------------------------------------------------

class SelfCheckPoller:
    """
    Self-check poller: periodically fetches this server's OWN /feed endpoint
    to confirm the feed stays reachable and well-formed.

    NOTE: this is a self-test, NOT Vision One. Vision One is an external
    TAXII 2.1 client that polls /taxii2/ on its own (see `taxii.auth`).
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.base_url = (self.config.get('base_url') or '').rstrip('/')
        self.client_id = self.config.get('client_id', '')
        self.name = self.config.get('name', 'Self-check')
        self.poll_interval = int(self.config.get('poll_interval', 60))
        self.subscription_name = self.config.get('subscription_name', 'Self-check feed')
        self.object_types = self.config.get(
            'object_types', ['ipv4-addr', 'file-hash', 'domain-name']
        )
        self.enabled = bool(self.config.get('enabled', False))
        self._stop = False
        self._thread: Optional[threading.Thread] = None

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for TAXII 2 requests."""
        auth = _get_taxii_auth_config()
        return {
            'X-Taxii-Username': auth.get('username', ''),
            'X-Taxii-Password': auth.get('password', ''),
        }

    def _poll_feed(self) -> Tuple[Optional[str], Optional[int]]:
        """Poll the /feed endpoint. Returns (xml_body, status_code)."""
        if not self.base_url:
            return None, None
        url = f"{self.base_url}/feed"
        req = urllib.request.Request(url, headers=self._get_auth_headers(), method='GET')
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read().decode('utf-8'), resp.status
        except urllib.error.HTTPError as exc:
            logger.warning("Self-check feed poll HTTP %s", exc.code)
            return None, exc.code
        except Exception as exc:
            logger.error("Self-check feed poll failed: %s", exc)
            return None, None

    def start(self) -> None:
        """Start background poller."""
        if self._thread and self._thread.is_alive():
            return
        self._stop = False
        self._thread = threading.Thread(target=self._poll_loop, name='SelfCheckPoller', daemon=True)
        self._thread.start()
        logger.info(
            "Self-check poller started (interval=%ss, server=%s)",
            self.poll_interval, self.base_url,
        )

    def stop(self) -> None:
        """Stop background poller."""
        self._stop = True
        if self._thread:
            self._thread.join(timeout=5)
            logger.info("Self-check poller stopped")

    def _poll_loop(self) -> None:
        while not self._stop:
            try:
                xml_data, status = self._poll_feed()
                if xml_data and status == 200:
                    logger.info("Self-check poll succeeded, response length: %s", len(xml_data))
                elif xml_data is None:
                    logger.warning("Self-check poll failed or incomplete")
            except Exception as exc:
                logger.error("Self-check poll error: %s", exc)
            if not self._stop:
                time.sleep(self.poll_interval)


_IPV4_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
_HASH_RE = re.compile(r'^[0-9a-fA-F]+$', re.ASCII)
_DOMAIN_RE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?)+$')


def _guess_object_type(value: str) -> Tuple[str, Optional[str]]:
    """Guess (stix_type, hash_algorithm) for a raw SOL value."""
    if _IPV4_RE.match(value):
        return 'ipv4-addr', None
    if _HASH_RE.match(value):
        algos = {32: 'md5', 40: 'sha1', 64: 'sha256'}
        algo = algos.get(len(value))
        if algo:
            return 'file-hash', algo
    if _DOMAIN_RE.match(value):
        return 'domain-name', None
    return 'indicator', None


def _is_valid_ipv4(value: str) -> bool:
    """True for a syntactically valid IPv4 address (each octet 0-255)."""
    if not _IPV4_RE.match(value):
        return False
    try:
        return all(0 <= int(o) <= 255 for o in value.split('.'))
    except (ValueError, AttributeError):
        return False


# ---------------------------------------------------------------------------
# CSV import (GT-team ad-hoc intel uploads) with fuzzy header mapping
# ---------------------------------------------------------------------------
# Accepts a CSV with ANY reasonable headers ("IP_Address", "src_ip",
# "Destination", "domain", "malicious_domain", ...) and maps them to our
# STIX object types by fuzzy matching + value validation.

# (normalized-header-contains -> column role), first match wins
_CSV_HEADER_RULES: List[Tuple[str, str]] = [
    ('indicator', 'indicator'), ('ioc', 'indicator'), ('value', 'indicator'),
    ('sha512', 'hash'), ('sha1', 'hash'), ('sha256', 'hash'),
    ('md5', 'hash'), ('hash', 'hash'),
    ('label', 'label'),
    ('domain', 'domain'), ('host', 'domain'), ('fqdn', 'domain'),
    ('srcip', 'ip'), ('dstip', 'ip'), ('ip', 'ip'), ('dest', 'ip'),
    ('name', 'name'),
    ('description', 'description'), ('desc', 'description'),
    ('confidence', 'confidence'), ('conf', 'confidence'),
]

_HASH_LEN_ALGO = {32: 'md5', 40: 'sha1', 64: 'sha256', 128: 'sha512'}


def _csv_classify_header(header: str) -> str:
    """Fuzzy-map a header cell to a column role."""
    norm = re.sub(r'[^a-z0-9]', '', (header or '').lower())
    for token, role in _CSV_HEADER_RULES:
        if token in norm:
            return role
    return 'ignore'


def _guess_hash_algo(value: str) -> str:
    return _HASH_LEN_ALGO.get(len(value), 'sha256')


def parse_csv_intel(text: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Parse CSV text into (stix_objects, skipped_rows).

    Headers are fuzzy-mapped; values are validated (IPv4 octets, domain
    shape, hash length) and re-classified when needed. Returns STIX
    ingest payloads ready for ``ingest_objects(..., source='manual')``.
    """
    try:
        reader = csv.DictReader(io.StringIO(text or ''))
        rows = list(reader)
    except Exception:
        return [], [{'error': 'could not parse CSV'}]

    if not rows or not reader.fieldnames:
        return [], [{'error': 'empty CSV (no header row found)'}]

    # Resolve column roles from the header row. A role may span several
    # columns (e.g. both "src_ip" and "dst_ip"); each recognized column is
    # remembered and the row loop takes the first valid value per role.
    roles: Dict[str, str] = {}
    for h in reader.fieldnames:
        role = _csv_classify_header(h)
        if role != 'ignore':
            roles[h] = role

    objects: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    # Emit one object per recognizable value column in a row (a row can carry
    # both an IP and a domain).
    value_roles = ('ip', 'domain', 'hash', 'indicator')
    for idx, raw in enumerate(rows, start=2):  # row 1 = header
        labels: List[str] = []
        confidence = 50
        for h, role in roles.items():
            cell = (raw.get(h) or '').strip()
            if not cell:
                continue
            if role == 'label':
                labels.extend(x.strip() for x in cell.split(',') if x.strip())
            elif role == 'confidence':
                try:
                    confidence = max(0, min(100, int(float(cell))))
                except ValueError:
                    pass

        emitted = False
        for vrole in value_roles:
            for h, r2 in roles.items():
                if r2 != vrole:
                    continue
                cell = (raw.get(h) or '').strip()
                if not cell:
                    continue
                if vrole == 'ip' and _is_valid_ipv4(cell):
                    value, otype, algo = cell, 'ipv4-addr', 'ipv4'
                elif vrole == 'domain' and _DOMAIN_RE.match(cell):
                    value, otype, algo = cell, 'domain-name', 'domain'
                elif vrole == 'hash' and re.fullmatch(
                        r'[0-9a-fA-F]+', cell) and len(cell) in _HASH_LEN_ALGO:
                    value, otype, algo = cell.lower(), 'file-hash', _guess_hash_algo(cell)
                elif vrole == 'indicator':
                    value, otype, algo = cell, 'indicator', 'indicator'
                else:
                    continue
                if otype == 'ipv4-addr':
                    obj_id = 'ipv4-addr--' + value.replace('.', '-')
                    obj = {'ipv4-addr': {'value': value}}
                elif otype == 'domain-name':
                    obj_id = 'domain-name--' + value.replace('.', '-')
                    obj = {'domain-name': {'value': value}}
                elif otype == 'file-hash':
                    obj_id = 'file-hash--' + value[:16]
                    obj = {'hash_value': {'algorithm': algo, 'value': value}}
                else:
                    obj_id = 'indicator--' + value[:16]
                    obj = {'indicator': {'value': value}}
                row_labels = [algo] if otype == 'file-hash' else list(labels)
                objects.append({
                    'id': obj_id,
                    'type': otype,
                    'object': obj,
                    'labels': row_labels,
                    'confidence': confidence,
                })
                emitted = True
                # do NOT break — every valid column of this role yields
                # its own object (e.g. src_ip AND dst_ip in one row).
        if not emitted:
            skipped.append({'row': idx, 'error': 'no recognizable value'})
    return objects, skipped


@app.route('/feed/import-csv', methods=['POST'])
def import_csv_data():
    """POST /feed/import-csv — GT-team CSV upload with fuzzy headers.

    Form field ``file`` (multipart) or raw CSV body. Merges in as
    ``source='manual'`` (append-only upsert — does NOT wipe existing rows),
    so the web UI "replace" semantics are not disturbed.
    """
    if not _request_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    text = None
    if 'file' in request.files:
        f = request.files['file']
        if not f or not f.filename:
            return jsonify({'error': 'no file provided'}), 400
        text = f.read().decode('utf-8-sig', errors='replace')
    else:
        text = request.get_data(as_text=True)
    if not text or not text.strip():
        return jsonify({'error': 'empty CSV'}), 400
    try:
        objects, skipped = parse_csv_intel(text)
    except Exception as exc:
        logger.error("CSV import error: %s", exc)
        return jsonify({'error': str(exc)}), 500
    if not objects:
        return jsonify({
            'imported': 0,
            'skipped': skipped[:50],
            'error': 'no recognizable rows (check headers/values)',
        }), 400
    try:
        added = ingest_objects(objects, mode='merge', source='manual')
    except Exception as exc:
        logger.error("CSV ingest error: %s", exc)
        return jsonify({'error': str(exc)}), 500
    return jsonify({
        'imported': added,
        'skipped': skipped[:50],
        'skipped_total': len(skipped),
    }), 200


# OTX indicator type -> (our object type, hash algorithm if any)
_OTX_TYPE_MAP = {
    'IPv4': ('ipv4-addr', None),
    'domain': ('domain-name', None),
    'hostname': ('domain-name', None),
    'FileHash-MD5': ('file-hash', 'md5'),
    'FileHash-SHA1': ('file-hash', 'sha1'),
    'FileHash-SHA256': ('file-hash', 'sha256'),
}


class OtxPoller:
    """
    Pulls community threat intelligence FROM AlienVault OTX into the feed.

    OTX publishes "pulses" (intel packets with indicators: IPs, domains,
    file hashes, URLs, ...). The puller lists recently updated public
    pulses and ingests their indicators in *merge* mode, tagged
    ``source='otx'`` — so it never wipes manual/web-UI intel, and a UI
    save never wipes OTX intel.

    OTX's legacy REST endpoints (``/otxapi/...``) are public and require
    no API key for read-only pulse browsing; an optional ``api_key``
    (free, from otx.alienvault.com) raises OTX rate limits.

    Config block (``otx:`` in config.yaml):
        enabled: true
        base_url: https://otx.alienvault.com   # no trailing slash
        api_key: ''                            # optional free OTX API key
        poll_interval: 300
        max_pulses: 25                         # pulses inspected per poll
        min_indicator_count: 1                 # skip pulses below this
        max_indicators_per_pulse: 1000         # cap indicators per pulse
        max_indicators_per_poll: 5000          # total cap per poll
        object_types: [ipv4-addr, domain-name, file-hash]
    """

    SOURCE = 'otx'

    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.base_url = (self.config.get('base_url') or 'https://otx.alienvault.com').rstrip('/')
        self.api_key = self.config.get('api_key') or ''
        self.poll_interval = int(self.config.get('poll_interval', 300))
        self.max_pulses = int(self.config.get('max_pulses', 25))
        self.min_indicator_count = int(self.config.get('min_indicator_count', 1))
        self.max_indicators_per_pulse = int(self.config.get('max_indicators_per_pulse', 1000))
        self.max_indicators_per_poll = int(self.config.get('max_indicators_per_poll', 5000))
        self.object_types = self.config.get(
            'object_types', ['ipv4-addr', 'domain-name', 'file-hash']
        )
        self.enabled = bool(self.config.get('enabled', False))
        self._stop = False
        self._thread: Optional[threading.Thread] = None
        self.last_poll_at: Optional[datetime] = None
        self.last_poll_added = 0

    def _headers(self) -> Dict[str, str]:
        headers = {
            'Accept': 'application/json',
            'User-Agent': 'TAXII-Server-OTX-Puller/1.0',
        }
        if self.api_key:
            headers['X-OTX-API-KEY'] = self.api_key
        return headers

    def _get_json(self, url: str) -> Optional[Any]:
        """GET a JSON URL; returns parsed body or None on error."""
        req = urllib.request.Request(url, headers=self._headers(), method='GET')
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as exc:
            logger.error("OTX HTTP %s for %s", exc.code, url.split('?')[0])
            return None
        except Exception as exc:
            logger.error("OTX request failed for %s: %s", url.split('?')[0], exc)
            return None

    def fetch_recent_pulses(self) -> List[Dict[str, Any]]:
        """List recently updated public pulses (newest first)."""
        url = (f'{self.base_url}/otxapi/pulses/?sort=-modified'
               f'&limit={min(self.max_pulses, 100)}')
        data = self._get_json(url)
        if not isinstance(data, dict):
            return []
        return [p for p in data.get('results', []) if isinstance(p, dict)]

    def fetch_pulse_indicators(self, pulse_id: str) -> List[Dict[str, Any]]:
        """Fetch (a capped page of) a pulse's indicators."""
        url = (f'{self.base_url}/otxapi/pulses/{pulse_id}/indicators/'
               f'?limit={min(self.max_indicators_per_pulse, 5000)}')
        data = self._get_json(url)
        if not isinstance(data, dict):
            return []
        return [i for i in data.get('results', []) if isinstance(i, dict)]

    def otx_indicator_to_stix(self, item: Dict[str, Any], pulse_name: str,
                              index: int) -> Optional[Dict[str, Any]]:
        """Map a raw OTX indicator to an ingestable STIX object descriptor.

        Returns None for indicator types we don't consume (URL, YARA, ...)
        or for values outside the configured ``object_types``.
        """
        raw_value = item.get('indicator') or ''
        raw_type = (item.get('type') or '').strip()
        if not raw_value or not isinstance(raw_value, str):
            return None

        raw_value = raw_value.strip()
        mapped = _OTX_TYPE_MAP.get(raw_type)
        if mapped is None:
            # Unknown OTX type: try to recognize the value shape (e.g. an
            # 'email' address is not in our model -> skip, not guess).
            if raw_type in ('YARA', 'URL', 'URI', 'IPV6', 'email', 'port', 'md5'):
                return None
            guessed, algo = _guess_object_type(raw_value)
            if guessed not in self.object_types:
                return None
            mapped = (guessed, algo)

        obj_type, algo = mapped
        if obj_type not in self.object_types:
            return None

        # Basic value sanity (OTX data is community-sourced).
        if obj_type == 'ipv4-addr' and not _IPV4_RE.match(raw_value):
            return None
        if obj_type == 'domain-name' and not _DOMAIN_RE.match(raw_value):
            return None
        if obj_type == 'file-hash' and not _HASH_RE.match(raw_value):
            return None

        pulse_ref = pulse_name or 'pulse'
        labels = ['otx', pulse_ref]
        confidence = 70  # community-sourced default; tune per deployment

        if obj_type == 'file-hash':
            algorithm = algo or 'sha256'
            payload = {'hash_value': {'algorithm': algorithm, 'value': raw_value}}
            stix_id = f"file-hash--{raw_value[:16]}"
            labels = [algorithm] + labels
        elif obj_type == 'ipv4-addr':
            payload = {'ipv4-addr': {'value': raw_value}}
            stix_id = f"ipv4-addr--{raw_value.replace('.', '-')}"
        elif obj_type == 'domain-name':
            payload = {'domain-name': {'value': raw_value}}
            stix_id = f"domain-name--{raw_value.replace('.', '-')}"
        else:
            payload = {'indicator': {'value': raw_value}}
            stix_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_OID, raw_value).hex[:16]}"

        return {
            'id': stix_id,
            'type': obj_type,
            'object': payload,
            'labels': labels,
            'confidence': confidence,
            'description': f'Pulled from OTX pulse "{pulse_ref}" '
                           f'(OTX type: {raw_type})',
        }

    def _poll_once(self) -> int:
        """One poll cycle: fetch recent OTX pulses, map indicators, merge.

        Returns the number of objects ingested in this cycle.
        """
        if not self.base_url:
            logger.warning("OTX poller misconfigured (base_url missing)")
            return 0

        stix_objects: List[Dict[str, Any]] = []
        for pulse in self.fetch_recent_pulses():
            if len(stix_objects) >= self.max_indicators_per_poll:
                break
            pulse_id = pulse.get('id') or ''
            if not pulse_id:
                continue
            if int(pulse.get('indicator_count') or 0) < self.min_indicator_count:
                continue

            for item in self.fetch_pulse_indicators(pulse_id):
                stix = self.otx_indicator_to_stix(item, pulse.get('name') or '', 0)
                if stix:
                    stix_objects.append(stix)
                    if len(stix_objects) >= self.max_indicators_per_poll:
                        break

        if not stix_objects:
            self.last_poll_at = datetime.utcnow()
            self.last_poll_added = 0
            save_puller_state('otx', 'ok', 0, 'no new indicators')
            return 0

        added = ingest_objects(stix_objects, mode='merge', source=self.SOURCE)
        self.last_poll_at = datetime.utcnow()
        self.last_poll_added = added
        save_puller_state('otx', 'ok', added, f'{added} object(s) ingested')
        return added

    def status(self) -> Dict[str, Any]:
        """Dashboard status for the OTX puller."""
        st = read_puller_state('otx') or {}
        return {
            'name': 'AlienVault OTX',
            'kind': 'otx',
            'enabled': self.enabled,
            'running': bool(self._thread and self._thread.is_alive()),
            'base_url': self.base_url,
            'last_sync': st.get('last_sync'),
            'last_added': st.get('last_added', 0),
            'last_status': st.get('last_status'),
            'last_message': st.get('last_message'),
        }

    def pull_now(self) -> Dict[str, Any]:
        """Run one poll cycle synchronously (for the dashboard 'Pull now')."""
        if not self.base_url:
            return {'name': 'AlienVault OTX', 'added': 0,
                    'error': 'misconfigured (base_url missing)'}
        try:
            added = self._poll_once()
        except Exception as exc:
            save_puller_state('otx', 'error', 0, str(exc))
            return {'name': 'AlienVault OTX', 'added': 0, 'error': str(exc)}
        st = read_puller_state('otx') or {}
        return {
            'name': 'AlienVault OTX',
            'added': added,
            'error': None,
            'last_sync': st.get('last_sync'),
            'last_status': st.get('last_status'),
        }

    def start(self) -> None:
        """Start background poller."""
        if self._thread and self._thread.is_alive():
            return
        self._stop = False
        self._thread = threading.Thread(target=self._poll_loop, name='OtxPoller', daemon=True)
        self._thread.start()
        logger.info(
            "OTX poller started (interval=%ss, server=%s)",
            self.poll_interval, self.base_url,
        )

    def stop(self) -> None:
        """Stop background poller."""
        self._stop = True
        if self._thread:
            self._thread.join(timeout=5)
            logger.info("OTX poller stopped")

    def _poll_loop(self) -> None:
        while not self._stop:
            try:
                count = self._poll_once()
                if count:
                    logger.info("OTX poll ingested %s object(s)", count)
                else:
                    logger.info("OTX poll complete (0 new objects)")
            except Exception as exc:
                logger.error("OTX poll error: %s", exc)
            if not self._stop:
                time.sleep(self.poll_interval)


# ---------------------------------------------------------------------------
# Generic TAXII 2.1 puller — pulls objects FROM third-party TAXII servers
# ---------------------------------------------------------------------------

# STIX 2.1 object types we can map onto our store (type -> our object_type).
_STIX_TO_OUR_TYPE = {
    'ipv4-addr': 'ipv4-addr',
    'domain-name': 'domain-name',
    'file': 'file-hash',
    'indicator': 'indicator',
}
_HASH_ALGO_BY_STIX_KEY = {
    'MD5': 'md5', 'SHA-1': 'sha1', 'SHA-256': 'sha256', 'SHA-512': 'sha512',
}


def _stix21_object_to_our(o: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Map a raw STIX 2.1 object (ipv4-addr / domain-name / file / indicator)
    to an ingestable descriptor. Returns None for unsupported/invalid objects.
    """
    stype = o.get('type')
    if stype not in _STIX_TO_OUR_TYPE:
        return None
    our_type = _STIX_TO_OUR_TYPE[stype]

    if our_type == 'ipv4-addr':
        value = o.get('value')
        if not value or not _is_valid_ipv4(str(value)):
            return None
        payload = {'ipv4-addr': {'value': value}}
        stix_id = f"ipv4-addr--{str(value).replace('.', '-')}"
        labels = list(o.get('labels') or [])
        name = None
    elif our_type == 'domain-name':
        value = o.get('value')
        if not value or not _DOMAIN_RE.match(str(value)):
            return None
        payload = {'domain-name': {'value': value}}
        stix_id = f"domain-name--{str(value).replace('.', '-')}"
        labels = list(o.get('labels') or [])
        name = None
    elif our_type == 'file-hash':
        hashes = o.get('hashes') or {}
        algo = None
        value = None
        for key, val in hashes.items():
            algo = _HASH_ALGO_BY_STIX_KEY.get(str(key).upper(), 'sha256')
            value = val
            break
        if not value:
            return None
        if not _HASH_RE.match(str(value)):
            return None
        payload = {'hash_value': {'algorithm': algo, 'value': str(value)}}
        stix_id = f"file-hash--{str(value)[:16]}"
        labels = [algo] + list(o.get('labels') or [])
        name = None
    else:  # indicator
        value = None
        pattern = o.get('pattern') or ''
        m = re.search(r"= '([^']+)'", pattern)
        if m:
            value = m.group(1)
        if not value:
            value = o.get('value') or o.get('name') or o.get('description')
        if not value:
            return None
        guessed, _ = _guess_object_type(str(value))
        if guessed == 'ipv4-addr' and _is_valid_ipv4(str(value)):
            stix_id = f"ipv4-addr--{str(value).replace('.', '-')}"
        elif guessed == 'domain-name' and _DOMAIN_RE.match(str(value)):
            stix_id = f"domain-name--{str(value).replace('.', '-')}"
        else:
            stix_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_OID, str(value)).hex[:16]}"
        our_type = guessed if guessed in ('ipv4-addr', 'domain-name') else 'indicator'
        if our_type == 'ipv4-addr':
            payload = {'ipv4-addr': {'value': str(value)}}
        elif our_type == 'domain-name':
            payload = {'domain-name': {'value': str(value)}}
        else:
            payload = {'indicator': {'value': str(value)}}
        labels = list(o.get('labels') or [])
        name = o.get('name')

    return {
        'id': stix_id,
        'type': our_type,
        'object': payload,
        'labels': labels or [],
        'confidence': int(o.get('confidence', 0) or 0) or 50,
        'name': name,
    }


class TaxiiPuller:
    """
    Pulls STIX 2.1 objects FROM a third-party TAXII 2.1 server into the feed.

    Any TAXII 2.1 server can be configured (not just OTX): discover its API
    root, pick a collection, and this puller polls it with HTTP Basic auth,
    honoring the server's ``?since=`` delta capability. Pulled objects are
    ingested in *merge* mode tagged with the puller's ``source`` (e.g.
    'otx-taxii', 'acme-taxii') so they are:
      * independent of manual intel, and
      * subject to the community intel gate (source != 'manual').

    Config block (one entry in the top-level ``taxii_pullers:`` list):
        name: otx-taxii                 # id / source tag / dashboard label
        base_url: https://server/taxii2/  # API Root URL (trailing slash ok)
        username: user
        password: pass
        collection: threat-intel         # collection id to poll
        poll_interval: 300
        max_objects_per_poll: 5000
        enabled: true
    """

    KIND = 'taxii'

    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.name = str(self.config.get('name') or 'taxii').strip() or 'taxii'
        self.base_url = (self.config.get('base_url') or '').rstrip('/')
        self.username = self.config.get('username') or ''
        self.password = self.config.get('password') or ''
        self.collection = (self.config.get('collection') or '').strip().lstrip('/')
        self.poll_interval = int(self.config.get('poll_interval', 300))
        self.max_objects_per_poll = int(self.config.get('max_objects_per_poll', 5000))
        self.enabled = bool(self.config.get('enabled', False))
        self._stop = False
        self._thread: Optional[threading.Thread] = None
        self.state_id = f'taxii:{self.name}'

    def _headers(self, url: str, since: Optional[str] = None) -> Dict[str, str]:
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'User-Agent': 'TAXII-Server-Puller/1.0',
        }
        if self.username:
            token = base64.b64encode(
                f'{self.username}:{self.password}'.encode('utf-8')
            ).decode('ascii')
            headers['Authorization'] = f'Basic {token}'
        return headers

    def _api_root_url(self) -> str:
        return self.base_url + '/' if not self.base_url.endswith('/') else self.base_url

    def _get_taxii(self, path: str, since: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """GET a TAXII 2.1 resource under the API root; returns parsed JSON."""
        url = self._api_root_url() + path
        if since:
            url += (('&' if '?' in url else '?') + f'since={since}')
        req = urllib.request.Request(url, headers=self._headers(url), method='GET')
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as exc:
            logger.error("TAXII pull %s HTTP %s (%s)", self.name, exc.code, url)
            return None
        except Exception as exc:
            logger.error("TAXII pull %s failed: %s", self.name, exc)
            return None

    def _fetch_objects(self, since: Optional[str]) -> List[Dict[str, Any]]:
        """Fetch STIX 2.1 objects from the configured collection (up to cap)."""
        if not self.collection:
            return []
        data = self._get_taxii(f'collections/{self.collection}/objects/', since)
        if not isinstance(data, dict):
            return []
        content = data.get('content') or {}
        bundle = content.get('content') or {}
        objects = bundle.get('objects') or []
        return [o for o in objects if isinstance(o, dict)][:self.max_objects_per_poll]

    def _poll_once(self) -> Tuple[int, Optional[str]]:
        """One poll cycle: ?since= poll the collection, map, merge.

        Returns (added, error_message_or_None).
        """
        if not self.base_url or not self.collection:
            return 0, 'misconfigured (base_url/collection missing)'

        since = _puller_since_iso(self.state_id)
        raw_objects = self._fetch_objects(since)
        if raw_objects is None:
            return 0, 'fetch failed (see server log)'

        stix_objects = [
            desc for desc in (_stix21_object_to_our(o) for o in raw_objects)
            if desc is not None
        ]
        if not stix_objects:
            save_puller_state(self.state_id, 'ok', 0, 'no new objects')
            return 0, None

        added = ingest_objects(stix_objects, mode='merge', source=self.name)
        save_puller_state(self.state_id, 'ok', added, f'{added} object(s) ingested')
        return added, None

    def pull_now(self) -> Dict[str, Any]:
        """Run one poll cycle synchronously (for the dashboard 'Pull now')."""
        added, err = self._poll_once()
        st = read_puller_state(self.state_id) or {}
        return {
            'name': self.name,
            'added': added,
            'error': err,
            'last_sync': st.get('last_sync'),
            'last_status': st.get('last_status'),
        }

    def status(self) -> Dict[str, Any]:
        """Dashboard status for this TAXII puller."""
        st = read_puller_state(self.state_id) or {}
        return {
            'name': self.name,
            'kind': self.KIND,
            'enabled': self.enabled,
            'running': bool(self._thread and self._thread.is_alive()),
            'base_url': self.base_url,
            'collection': self.collection,
            'last_sync': st.get('last_sync'),
            'last_added': st.get('last_added', 0),
            'last_status': st.get('last_status'),
            'last_message': st.get('last_message'),
        }

    def start(self) -> None:
        """Start background poller."""
        if self._thread and self._thread.is_alive():
            return
        self._stop = False
        self._thread = threading.Thread(
            target=self._poll_loop, name=f'TaxiiPuller-{self.name}', daemon=True
        )
        self._thread.start()
        logger.info(
            "TAXII puller '%s' started (interval=%ss, server=%s)",
            self.name, self.poll_interval, self.base_url,
        )

    def stop(self) -> None:
        """Stop background poller."""
        self._stop = True
        if self._thread:
            self._thread.join(timeout=5)
            logger.info("TAXII puller '%s' stopped", self.name)

    def _poll_loop(self) -> None:
        while not self._stop:
            try:
                added, err = self._poll_once()
                if added:
                    logger.info("TAXII pull '%s' ingested %s object(s)", self.name, added)
                elif err:
                    logger.warning("TAXII pull '%s': %s", self.name, err)
            except Exception as exc:
                logger.error("TAXII pull '%s' error: %s", self.name, exc)
            if not self._stop:
                time.sleep(self.poll_interval)


# ---------------------------------------------------------------------------
# Module-level instances & initialization
# ---------------------------------------------------------------------------

# Community intel puller (OTX). The old reverse-direction "trend_micro"
# (Apex SOL) puller has been removed — data flows community -> this server
# -> Vision One, not from Trend Micro.
otx_poller = OtxPoller(CONFIG.get('otx', {}) or {})
# "self_check" is the current key; fall back to the legacy "vision_one" key
# for anyone who hasn't updated their config yet.
self_check_poller = SelfCheckPoller(
    CONFIG.get('self_check', {}) or CONFIG.get('vision_one', {}) or {}
)

# Backward-compatible alias (the self-check poller was previously named
# "vision_one", which was misleading — Vision One is the external TAXII client).
VisionOnePoller = SelfCheckPoller

# Generic third-party TAXII 2.1 pullers (top-level `taxii_pullers:` list).
taxii_pullers: List[TaxiiPuller] = [
    TaxiiPuller(cfg) for cfg in (CONFIG.get('taxii_pullers') or [])
    if isinstance(cfg, dict) and cfg.get('name')
]

# Initialize database tables at import time (endpoints and tests rely on it).
init_db()


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    """Application entry point.

    Note: Vision One is NOT started here. It is an external TAXII 2.1 client
    that polls /taxii2/ on its own (configured with taxii.auth). Only the
    optional background pollers below start, and both are off by default.
    """
    # Restore ingested intel that persisted in the DB so the feed is complete
    # even on the first poll after a restart.
    rehydrate_memory()

    # Auto-revoke any indicators that expired while the server was down,
    # then start the periodic TTL sweeper.
    sweep_expired_indicators()
    start_ttl_sweeper()

    if otx_poller.enabled and otx_poller.base_url:
        otx_poller.start()
    for puller in taxii_pullers:
        if puller.enabled and puller.base_url and puller.collection:
            puller.start()
    if self_check_poller.enabled and self_check_poller.base_url:
        self_check_poller.start()

    server_cfg = CONFIG.get('server', {}) or {}
    app.run(
        host=server_cfg.get('host', '0.0.0.0'),
        port=int(server_cfg.get('port', 5000)),
        debug=bool(server_cfg.get('debug', False)),
    )


if __name__ == '__main__':
    main()
