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
    Optional background pollers (all off by default):
        - otx        : pull community intel FROM AlienVault OTX (pulses/indicators)
        - abuse_ch   : pull community intel FROM abuse.ch (ThreatFox/Feodo/URLhaus)
        - taxii      : pull objects from any third-party TAXII 2.1 server
        - self_check : self-test that polls our own /feed for reachability
    Optional enrichment (on demand, off by default):
        - virus_total: cached VirusTotal lookups (a false-positive tie-breaker)
"""

import base64
import argparse
import csv
import hashlib
import hmac
import html
import io
import ipaddress
import json
import logging
import os
import re
import secrets
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
from flask import (Flask, Response, g, jsonify, make_response, redirect,
                   request, send_from_directory)
from flask_cors import CORS
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    and_,
    create_engine,
    func,
    or_,
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
    value = Column(String, nullable=True)        # generic single-value SCOs (url,
                                                 # email-addr, ipv6-addr, mac-addr, ...)
    source_ref = Column(String, nullable=True)   # STIX relationship source_ref
    target_ref = Column(String, nullable=True)   # STIX relationship target_ref
    relationship_type = Column(String, nullable=True)  # STIX relationship_type
    object_refs = Column(Text, nullable=True)    # report object_refs (JSON list)
    valid_from = Column(DateTime, nullable=True)  # STIX valid_from (upstream, when known)
    collection_id = Column(String, default='threat-intel', index=True)  # which TAXII
                                                 # collection this object belongs to
    source = Column(String, nullable=True)       # origin: 'manual' | 'otx'
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    revoked = Column(Boolean, default=False)
    revoked_at = Column(DateTime, nullable=True)   # when it was revoked (UTC)
    created = Column(DateTime, default=datetime.utcnow)
    modified = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # Scoring pipeline (see "Scoring pipeline — Phase 1"). NULL = never scored
    # (e.g. manual intel, or the feature was off when it was ingested) — which
    # is deliberately distinct from a score of 0, so "unscored" can be treated
    # as its own policy rather than silently reading as "worst possible".
    score = Column(Integer, nullable=True)
    score_breakdown = Column(Text, nullable=True)   # JSON: {signal: points}
    scored_at = Column(DateTime, nullable=True)

    # TAXII Get Objects filters on `modified` and keyset-paginates on
    # (modified, stix_id) — without these every poll is a full scan + sort.
    # The collection-leading index also serves the per-collection poll.
    __table_args__ = (
        Index('ix_stix_objects_modified_id', 'modified', 'stix_id'),
        Index('ix_stix_objects_coll_modified_id', 'collection_id', 'modified',
              'stix_id'),
    )


class Subscription(Base):
    """ORM model for TAXII subscriptions."""

    __tablename__ = "subscriptions"

    id = Column(String, primary_key=True)
    client_id = Column(String, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    enabled = Column(Boolean, default=True)
    created = Column(DateTime, default=datetime.utcnow)
    last_verified = Column(DateTime, nullable=True)


class ApiKey(Base):
    """A scoped TAXII API key (dashboard-generated consumer credential).

    The plaintext secret is shown exactly once, at creation, and never
    stored. The cleartext ``prefix`` is kept and indexed so a presented key
    resolves to its row in one lookup and can be identified in listings and
    log lines; only a SHA-256 of the secret is persisted. Keys are
    high-entropy random values, so a fast hash is the correct choice here (as
    at GitHub/Stripe) — an adaptive hash (``generate_password_hash``) would
    run on every poll for no gain.

    ``collections`` is a JSON list of collection ids the key may read;
    ``rate_limit`` / ``rate_window`` are an optional per-key sliding window
    (requests per window seconds); ``max_objects`` is an optional ceiling on
    how many objects one response may carry for this key. Unlike
    :class:`Subscription` — a hashed-credential store the TAXII feed never
    consults — this table IS the credential the feed honours.
    """

    __tablename__ = "api_keys"

    id = Column(String, primary_key=True)
    label = Column(String, nullable=False, default='')
    prefix = Column(String, nullable=False, index=True)
    secret_hash = Column(String, nullable=False)
    enabled = Column(Boolean, default=True)
    created = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    collections = Column(Text, nullable=True)   # JSON list of collection ids
    rate_limit = Column(Integer, nullable=True)    # requests per window (0/null = off)
    rate_window = Column(Integer, nullable=True)   # window length, seconds
    # Per-response IOC ceiling for this key. Bounds how many objects one Get
    # Objects response may carry, so a consumer with a per-poll ingest limit
    # cannot be handed the whole feed at once. 0/null inherits
    # taxii.max_objects. NOTE: this only throttles *delivery* — the client must
    # follow `more`/`next` (or poll with added_after) to make progress, or it
    # will keep receiving the same first page.
    max_objects = Column(Integer, nullable=True)
    # Object-TYPE allow-list for this key: a JSON list of stored STIX object
    # types (see _SUPPORTED_STIX_TYPES) the key may be SERVED by Get Objects.
    # Unlike max_objects (a delivery throttle), this narrows entitlement: a
    # type outside the list is never returned. NULL (a legacy row) means "all
    # types" — init_db backfills existing keys with the full list so their
    # behaviour is unchanged. Enforced only on the /taxii2/ read path.
    types = Column(Text, nullable=True)


class IocObservation(Base):
    """One sighting of a value by one source.

    The merged ``stix_objects`` row is keyed by an id derived from the value,
    so when OTX and ThreatFox both report the same IOC they collapse into ONE
    row and the second source is lost. This table keeps every sighting, which
    is what makes a cross-source score possible: corroboration is "how many
    independent sources observed this", and that fact exists only here.

    ``observation_key`` dedupes within a source (e.g. the OTX pulse id), so
    re-polling the same pulse refreshes ``last_seen`` instead of inflating the
    count. ``detail`` carries source-specific signals (pulse adversary/tags,
    ThreatFox malware family, ...) as JSON.
    """

    __tablename__ = "ioc_observations"

    id = Column(String, primary_key=True)
    value = Column(String, nullable=False, index=True)   # normalised (lowercased)
    object_type = Column(String, nullable=False)
    source = Column(String, nullable=False, index=True)  # otx | threatfox | feodo | ...
    observation_key = Column(String, nullable=False)     # dedupe within a source
    observed_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    raw_confidence = Column(Integer, nullable=True)      # source's own 0-100
    detail = Column(Text, nullable=True)                 # JSON

    __table_args__ = (
        UniqueConstraint('value', 'source', 'observation_key',
                         name='uq_ioc_observation'),
    )


class UIUser(Base):
    """A dashboard login with a role.

    Replaces the single shared ``ui.auth`` pair for everyday use. Passwords
    are hashed with werkzeug (scrypt/pbkdf2) — unlike API keys this runs once
    per *login*, not per poll, so an adaptive hash is the right choice.

    ``role`` is one of :data:`ROLE_LEVELS` and is resolved from this row on
    every request rather than baked into the session cookie, so disabling a
    user or changing their role takes effect immediately instead of at their
    next login. The static ``ui.auth`` credential is kept as a virtual
    break-glass admin and is deliberately NOT stored here.
    """

    __tablename__ = "ui_users"

    id = Column(String, primary_key=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default='viewer')
    enabled = Column(Boolean, default=True)
    created = Column(DateTime, default=datetime.utcnow)
    last_login_at = Column(DateTime, nullable=True)


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


class AuditEvent(Base):
    """Append-only audit trail of dashboard mutations and successful logins.

    The server already logs every mutation as a *line* (``logger.info(... by
    %s, _actor())``), but a log line is not queryable in-app. This table makes
    "which user changed what, and from where" answerable through
    ``GET /ui/audit`` (admin only) and the dashboard's Audit log tab.

    Rows are written only on success, only for the actions in
    :data:`AUDIT_ACTIONS`, and NEVER carry secrets (an API-key create records
    the prefix, never the plaintext). There is deliberately no ``onupdate``:
    an audit row is written once and never mutated. Retention is bounded by
    :func:`prune_audit_events`; ``retention_days: 0`` keeps rows forever.
    """

    __tablename__ = "audit_events"

    id = Column(String, primary_key=True)            # uuid4().hex
    created = Column(DateTime, default=datetime.utcnow)  # naive UTC, like every other ts
    actor = Column(String, nullable=False)           # bare username; 'anonymous' if none
    role = Column(String, nullable=True)             # viewer | editor | admin
    via = Column(String, nullable=True)              # ui_auth | sso | session | admin_auth
    ip = Column(String, nullable=True)
    action = Column(String, nullable=False)          # 'feed.ingest', …
    target = Column(String, nullable=True)           # stix_id | username | prefix | collection
    collection = Column(String, nullable=True)
    count = Column(Integer, nullable=True)
    detail = Column(Text, nullable=True)             # human-readable summary
    __table_args__ = (
        Index('ix_audit_events_created_id', 'created', 'id'),
        Index('ix_audit_events_action_created', 'action', 'created'),
        Index('ix_audit_events_actor', 'actor'),
    )


class BenignValue(Base):
    """Known-legitimate value: kept OUT of the Vision One feed.

    The false-positive filter. The community gate's rules catch a *kind* of
    noise (private IPs, stale intel, low confidence), but none of them can know
    that ``login.microsoftonline.com`` is legitimate — so a community feed that
    flags it would otherwise be served, and Vision One would then block real
    traffic. A benign entry names a value that is exempt-from-serving: any
    community object whose value matches is WITHHELD from the feed.

    ``kind`` decides how ``value`` matches:
      * ``exact``  — one value (IP / domain / hash / name / URL), case-insensitive
      * ``domain`` — the value and any subdomain (``microsoft.com`` covers
                     ``login.microsoftonline.com``)
      * ``cidr``   — an IP network (e.g. a cloud / Office 365 / CDN range)

    The same three forms are also available statically in ``config.yaml``
    (``intel_filter.benign_values`` / ``benign_domains`` / ``benign_cidrs``);
    this table is the *dynamic* form, editable from the dashboard so a
    legitimate value can be filtered out without a config edit and restart.

    Manual intel (``source='manual'``) is never gated, so a benign entry does
    not affect it — only community-sourced objects are withheld.
    """

    __tablename__ = "benign_values"

    id = Column(String, primary_key=True)            # uuid4().hex
    value = Column(String, nullable=False, index=True)
    kind = Column(String, nullable=False, default='exact')  # exact | domain | cidr
    note = Column(String, nullable=True)             # why (free text, optional)
    created = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String, nullable=True)       # actor (user or 'anonymous')


class VtCache(Base):
    """Cached VirusTotal verdict for one value (on-demand enrichment).

    The free VirusTotal tier allows only ~4 requests/min and 500/day, so a
    lookup result is stored and reused until it ages out (``virus_total.cache_ttl``)
    — a repeat check of the same value never spends quota. One row per value
    (lowercased), upserted on each fresh lookup. This is a *tie-breaker* for the
    false-positive workflow: a flagged domain that VT reports as clean is a good
    candidate for the known-legitimate filter, and the operator decides.
    """

    __tablename__ = "vt_cache"

    value = Column(String, primary_key=True)     # lowercased value (URL kept whole)
    kind = Column(String, nullable=False)        # ip | domain | url | hash
    malicious = Column(Integer, default=0)
    suspicious = Column(Integer, default=0)
    harmless = Column(Integer, default=0)
    undetected = Column(Integer, default=0)
    reputation = Column(Integer, nullable=True)
    categories = Column(String, nullable=True)   # comma-joined VT categories
    link = Column(String, nullable=True)         # VT GUI permalink
    fetched = Column(DateTime, default=datetime.utcnow)
    fetched_by = Column(String, nullable=True)   # actor (user or 'anonymous')


def _utc_now_iso() -> str:
    """Current UTC time as ISO-8601 'Z' (STIX 2.1 / TAXII ?since= format)."""
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')


def _parse_iso_ts(value: Any) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp (with or without a trailing 'Z') to a naive
    UTC datetime, or None if it cannot be parsed."""
    s = str(value)
    for candidate in (s.replace('Z', '+00:00'), s):
        try:
            return datetime.fromisoformat(candidate)
        except ValueError:
            continue
    return None


def _parse_iso_naive(value: Any) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp to a naive UTC datetime (or None)."""
    dt = _parse_iso_ts(value)
    if dt is not None and dt.tzinfo is not None:
        dt = dt - dt.utcoffset()
    return dt


def create_session():
    """Create a new database session (caller is responsible for closing)."""
    return SessionLocal()


def _rehome_aggregate_rows() -> int:
    """Re-home rows stored under the pre-segregation collection id.

    Before this server split its feed, every object was written under the
    single legacy id (``DEFAULT_COLLECTION_ID``, 'threat-intel'). The
    aggregate that replaced it owns no rows of its own, so those rows would
    be invisible to every reader (and to Vision One). Split them by
    provenance: manual (and unknown-source) rows become the manual member,
    everything the pullers wrote becomes the community member.

    Idempotent by construction: the predicate matches the legacy id only, and
    no re-homed row carries it again, so a second run updates 0 rows. A no-op
    when the feature is off — either no aggregate is configured, or the
    legacy id is still a configured collection of its own.

    Returns the number of rows re-homed.
    """
    member_ids = [m for c in TAXII_COLLECTIONS if c.members for m in c.members]
    if not member_ids or DEFAULT_COLLECTION_ID in TAXII_COLLECTION_MAP:
        return 0
    # Derive the split targets from the configured members, not from
    # hardcoded ids: an operator who renames a leaf still gets the right
    # routing (with the first/last member standing in for a missing one).
    manual_target = (DEFAULT_MANUAL_COLLECTION_ID
                     if DEFAULT_MANUAL_COLLECTION_ID in member_ids
                     else member_ids[0])
    community_target = (DEFAULT_COMMUNITY_COLLECTION_ID
                        if DEFAULT_COMMUNITY_COLLECTION_ID in member_ids
                        else member_ids[-1])
    with engine.begin() as conn:
        rehomed_manual = conn.execute(
            text(
                "UPDATE stix_objects SET collection_id = :target "
                "WHERE collection_id = :legacy "
                "AND (source = 'manual' OR source IS NULL)"
            ),
            {'target': manual_target, 'legacy': DEFAULT_COLLECTION_ID},
        ).rowcount
        # Whatever is left under the legacy id came from a community puller.
        rehomed_community = conn.execute(
            text(
                "UPDATE stix_objects SET collection_id = :target "
                "WHERE collection_id = :legacy"
            ),
            {'target': community_target, 'legacy': DEFAULT_COLLECTION_ID},
        ).rowcount
    total = max(rehomed_manual, 0) + max(rehomed_community, 0)
    if total:
        logger.info(
            "Re-homed %s legacy row(s) out of '%s' (%s: %s, %s: %s)",
            total, DEFAULT_COLLECTION_ID, manual_target, rehomed_manual,
            community_target, rehomed_community,
        )
    return total


def init_db() -> None:
    """Initialize database tables (and apply lightweight column migrations).

    ``create_all`` is the schema source of truth: it creates every table the
    ORM defines (``stix_objects``, ``subscriptions``, ``puller_state``,
    ``api_keys``, ``ui_users``, ``audit_events``) that does not already exist,
    so pointing the server at an empty PostgreSQL database is all the
    provisioning it needs. The
    add-if-missing column loop below only matters for a database created by
    an older build.
    """
    try:
        Base.metadata.create_all(engine)
    except Exception as exc:
        # Fail with what to fix rather than a bare driver traceback: this is
        # the first thing that touches the database, so an unreachable or
        # mis-credentialed PostgreSQL shows up here.
        logger.error(
            "Could not create the schema in %r (%s: %s). Is PostgreSQL up and "
            "is DATABASE_URL/POSTGRES_* correct? In docker compose the database "
            "is the `postgres` service (docker compose up -d postgres).",
            DATABASE_URL, type(exc).__name__, exc,
        )
        raise
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
                    # TIMESTAMP, not SQLite's DATETIME: accepted by SQLite
                    # (type affinity) *and* by PostgreSQL, so the migration is
                    # portable across both.
                    text('ALTER TABLE stix_objects ADD COLUMN revoked_at TIMESTAMP')
                )
            logger.info("Migrated stix_objects: added 'revoked_at' column")
        # Extended STIX types (url/email/ipv6/mac/...), relationships, and
        # multi-collection support (idempotent; databases created after these
        # columns existed already have them).
        for col, ddl in (
            ('value', 'VARCHAR'),
            ('source_ref', 'VARCHAR'),
            ('target_ref', 'VARCHAR'),
            ('relationship_type', 'VARCHAR'),
            ('collection_id', 'VARCHAR'),
            ('object_refs', 'TEXT'),        # report object_refs (JSON list)
            ('valid_from', 'TIMESTAMP'),    # STIX valid_from (upstream; TIMESTAMP
                                            # works on both SQLite and Postgres)
            ('score', 'INTEGER'),           # scoring pipeline (Phase 1)
            ('score_breakdown', 'TEXT'),
            ('scored_at', 'TIMESTAMP'),
        ):
            if col not in cols:
                with engine.begin() as conn:
                    conn.execute(
                        text(f'ALTER TABLE stix_objects ADD COLUMN {col} {ddl}')
                    )
                logger.info("Migrated stix_objects: added '%s' column", col)
        # Backfill: pre-collection rows belong to the legacy single-collection
        # id (which _rehome_aggregate_rows below then splits by provenance).
        with engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE stix_objects SET collection_id = :legacy "
                    "WHERE collection_id IS NULL"
                ),
                {'legacy': DEFAULT_COLLECTION_ID},
            )
    # `api_keys` gained `max_objects` (the per-key response ceiling) after the
    # table first shipped; add it for a database created by an older build.
    # `create_all` above already includes it on a fresh database.
    if 'api_keys' in insp.get_table_names():
        key_cols = {c['name'] for c in insp.get_columns('api_keys')}
        if 'max_objects' not in key_cols:
            with engine.begin() as conn:
                conn.execute(
                    text('ALTER TABLE api_keys ADD COLUMN max_objects INTEGER')
                )
            logger.info("Migrated api_keys: added 'max_objects' column")
        # `types` (the per-key object-type allow-list) also arrived later. Add
        # it, then backfill every existing key with the FULL type list so the
        # now-strict allow-list does not silently strip types (reports,
        # relationships, …) from keys that predate the column.
        if 'types' not in key_cols:
            all_types = json.dumps(sorted(_SUPPORTED_STIX_TYPES))
            with engine.begin() as conn:
                conn.execute(text('ALTER TABLE api_keys ADD COLUMN types TEXT'))
                conn.execute(
                    text('UPDATE api_keys SET types = :all WHERE types IS NULL'),
                    {'all': all_types},
                )
            logger.info("Migrated api_keys: added 'types' column (backfilled)")

    # `create_all` only creates indexes for tables it creates, so a database
    # that predates the poll-path indexes above never gets them. Create any
    # missing ones explicitly — checkfirst makes this idempotent and portable
    # (MySQL/MariaDB have no CREATE INDEX IF NOT EXISTS).
    for index in STIXObject.__table__.indexes:
        index.create(bind=engine, checkfirst=True)
    # One-time re-homing of rows written under the pre-segregation collection
    # id. Runs AFTER the NULL backfill above, otherwise the backfilled rows
    # would be stranded under the legacy id rather than split by provenance.
    _rehome_aggregate_rows()
    # Log the backend and the tables that actually exist, so a deployment can
    # confirm the schema landed (and in which database) straight from the log.
    logger.info(
        "Database initialized (backend=%s, tables=%s)",
        engine.dialect.name,
        ', '.join(sorted(inspect(engine).get_table_names())) or 'none',
    )


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
                memory_store[row.stix_id] = _row_to_threat_intel(row)
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
# Audit log (who changed what — durable, queryable mutation trail)
# ---------------------------------------------------------------------------
# Every dashboard mutation (and every successful login) appends a row to
# `audit_events`, surfaced to admins at GET /ui/audit and in the dashboard's
# Audit log tab. This is observability, not correctness: a failed audit write
# is logged and swallowed so it can never change (or fail) the request it is
# recording. Retention is bounded below; `retention_days: 0` opts into keeping
# rows forever.

AUDIT_CFG: Dict[str, Any] = CONFIG.get('audit', {}) or {}
AUDIT_ENABLED = bool(AUDIT_CFG.get('enabled', True))
AUDIT_RETENTION_DAYS = AUDIT_CFG.get('retention_days', 90)
AUDIT_MAX_EVENTS = AUDIT_CFG.get('max_events', 100000)
AUDIT_PRUNE_INTERVAL = int(AUDIT_CFG.get('prune_interval', 86400) or 0)

# The complete set of recorded actions. Kept explicit so the dashboard's
# action filter and the tests can enumerate them, and a typo'd action at a
# call site is easy to spot. ('auth.login' is the one non-mutation.)
AUDIT_ACTIONS = (
    'object.revoke', 'object.unrevoke', 'feed.ingest', 'feed.delete',
    'feed.purge', 'feed.import', 'community.pull', 'key.create',
    'key.revoke', 'user.create', 'user.update', 'user.delete', 'auth.login',
    'benign.create', 'benign.delete',
)

# Field caps — audit text is operator-facing, not a data store, so oversize
# values are truncated rather than stored whole (a CSV import's id list, an
# error message, a huge form value).
_AUDIT_TARGET_MAX = 255
_AUDIT_DETAIL_MAX = 500


def prune_audit_events(now: Optional[datetime] = None) -> int:
    """Trim the audit trail to the configured retention window / count cap.

    Deletes rows older than ``retention_days`` (when > 0), then — if more than
    ``max_events`` remain — the oldest rows beyond that cap. Both knobs are
    optional (0/null = keep forever). Best-effort: a failure is logged and
    swallowed so the diagnostic thread can never take the server down.

    DESTRUCTIVE: pruned rows are gone. This is the documented cost of a bounded
    trail; set ``retention_days: 0`` and ``max_events: 0`` to keep everything.
    Returns the number of rows deleted.
    """
    if not AUDIT_ENABLED:
        return 0
    now = now or datetime.utcnow()
    session = create_session()
    try:
        deleted = 0
        if isinstance(AUDIT_RETENTION_DAYS, int) and AUDIT_RETENTION_DAYS > 0:
            cutoff = now - timedelta(days=AUDIT_RETENTION_DAYS)
            deleted += (session.query(AuditEvent)
                        .filter(AuditEvent.created < cutoff)
                        .delete(synchronize_session=False))
        if isinstance(AUDIT_MAX_EVENTS, int) and AUDIT_MAX_EVENTS > 0:
            total = session.query(AuditEvent).count()
            excess = total - AUDIT_MAX_EVENTS
            if excess > 0:
                # Drop the oldest `excess` rows (newest are the ones worth
                # keeping). Uses the created/id ordering the endpoint serves.
                cutoff_ids = [
                    row_id for (row_id,) in
                    session.query(AuditEvent.id)
                    .order_by(AuditEvent.created.asc(), AuditEvent.id.asc())
                    .limit(excess)
                    .all()
                ]
                if cutoff_ids:
                    deleted += (session.query(AuditEvent)
                                .filter(AuditEvent.id.in_(cutoff_ids))
                                .delete(synchronize_session=False))
        if deleted:
            session.commit()
            logger.info("Pruned %s audit event(s)", deleted)
        return deleted
    except Exception as exc:  # pragma: no cover - best-effort maintenance
        session.rollback()
        logger.error("Audit prune failed: %s", exc)
        return 0
    finally:
        session.close()


def start_audit_pruner() -> None:
    """Background thread that periodically prunes the audit trail.

    Skipped entirely when audit is disabled or both retention knobs are off
    (nothing to prune), so a keep-forever deployment runs no extra thread.
    """
    if not AUDIT_ENABLED:
        return
    time_capped = isinstance(AUDIT_RETENTION_DAYS, int) and AUDIT_RETENTION_DAYS > 0
    count_capped = isinstance(AUDIT_MAX_EVENTS, int) and AUDIT_MAX_EVENTS > 0
    if not (time_capped or count_capped) or AUDIT_PRUNE_INTERVAL <= 0:
        return

    def _loop() -> None:
        while True:
            try:
                time.sleep(AUDIT_PRUNE_INTERVAL)
                prune_audit_events()
            except Exception:  # pragma: no cover - best-effort loop guard
                pass

    thread = threading.Thread(target=_loop, name='AuditPruner', daemon=True)
    thread.start()
    logger.info(
        "Audit pruner started (interval=%ss, retention_days=%s, max_events=%s)",
        AUDIT_PRUNE_INTERVAL, AUDIT_RETENTION_DAYS, AUDIT_MAX_EVENTS,
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
    value: Optional[str] = None           # generic single-value SCOs (url, email-addr,
                                          # ipv6-addr, mac-addr, windows-registry-key, AS)
    source_ref: Optional[str] = None      # STIX relationship source_ref
    target_ref: Optional[str] = None      # STIX relationship target_ref
    relationship_type: Optional[str] = None  # STIX relationship_type
    object_refs: Optional[str] = None     # report object_refs (JSON list, as stored)
    valid_from: Optional[datetime] = None  # STIX valid_from (upstream, when known)
    collection: str = 'threat-intel'      # TAXII collection this object belongs to
    source: str = 'manual'
    revoked: bool = False  # once revoked -> served as STIX revoked: true
    # Stored STIX timestamps (mirrored from the row). These are what the feed
    # is *served* with: `created` is immutable per object and `modified` only
    # moves when the object actually changes. Stamping `now` at render time
    # instead would make every poll look like a full-feed change and break
    # `added_after` delta sync.
    created: Optional[datetime] = None
    modified: Optional[datetime] = None
    # Scoring pipeline: the computed 0-100 score and its per-signal breakdown.
    # None means "never scored", which the dashboard shows distinctly from 0.
    score: Optional[int] = None
    score_breakdown: Optional[str] = None   # JSON object, as stored

    def to_stix_object(self) -> Dict[str, Any]:
        """Convert to a STIX 2.1-flavoured object dict (see generate_taxii_bundle)."""
        labels = self.labels or []
        confidence = self.confidence or 0
        now = _stix_now()
        created = _stix_ts(self.created) or now
        modified = _stix_ts(self.modified) or created

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
        elif self.object_type in ("url", "email-addr", "ipv6-addr", "mac-addr",
                                  "windows-registry-key", "autonomous-system"):
            obj_dict["value"] = self.value or self.stix_id
        elif self.object_type in ("indicator", "malware", "malware-family",
                                  "threat-actor", "campaign"):
            obj_dict["value"] = self.name or "Threat Intel Indicator"
        elif self.object_type == "relationship":
            obj_dict["source_ref"] = self.source_ref or ''
            obj_dict["relationship_type"] = self.relationship_type or ''
            obj_dict["target_ref"] = self.target_ref or ''
        else:
            obj_dict["value"] = self.stix_id

        result: Dict[str, Any] = {
            "id": self.stix_id,
            "type": self.object_type,
            "created": created,
            "modified": modified,
            "revoked": bool(self.revoked),
            "labels": labels,
            "confidence": confidence,
            "object": obj_dict,
        }
        # Keep the hash addressable at the top level as well (consumers differ).
        if self.object_type == "file-hash":
            result["hash_value"] = obj_dict["hash_value"]
        return result


def _row_to_threat_intel(row: STIXObject) -> ThreatIntel:
    """Build a :class:`ThreatIntel` from a persisted ``STIXObject`` row.

    The single conversion used by both ``rehydrate_memory`` and the read
    paths, so what the feed serves is always derived from the row — the DB is
    the source of truth and a stale/missing memory entry can no longer change
    (or silently drop) a served object.
    """
    return ThreatIntel(
        stix_id=row.stix_id,
        object_type=row.object_type,
        labels=[l for l in (row.labels or '').split(',') if l],
        confidence=row.confidence or 0,
        name=row.name,
        description=row.description,
        hash_value=row.hash_value,
        ip_address=row.ip_address,
        domain=row.domain,
        value=row.value,
        source_ref=row.source_ref,
        target_ref=row.target_ref,
        relationship_type=row.relationship_type,
        object_refs=row.object_refs,
        valid_from=row.valid_from,
        collection=row.collection_id or 'threat-intel',
        source=row.source or 'manual',
        revoked=bool(row.revoked),
        created=row.created,
        modified=row.modified,
        score=row.score,
        score_breakdown=row.score_breakdown,
    )


# In-memory store (fast path for the dashboard / write coordination)
memory_store: Dict[str, ThreatIntel] = {}
memory_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Flask Application
# ---------------------------------------------------------------------------

app = Flask(__name__)
_flask_secret = str(CONFIG.get('security', {}).get('secret_key', '') or '')
if not _flask_secret:
    print('WARNING: FLASK_SECRET is not set — set it in .env (see '
          '.env.example). Session cookies will not be signable until then.',
          file=sys.stderr)
app.config['SECRET_KEY'] = _flask_secret
_taxii_auth_cfg = CONFIG.get('taxii', {}).get('auth', {}) or {}
app.config['TAXII_AUTH'] = {
    'username': _taxii_auth_cfg.get('username') or '',
    'password': _taxii_auth_cfg.get('password') or '',
}
if not app.config['TAXII_AUTH']['username'] or not app.config['TAXII_AUTH']['password']:
    # No legacy override; check whether per-collection credentials are
    # configured instead (taxii.collections:) before warning.
    taxii_entries = (CONFIG.get('taxii', {}) or {}).get('collections')
    has_collection_creds = isinstance(taxii_entries, list) and any(
        isinstance(e, dict) and (e.get('auth') or {}).get('username')
        and (e.get('auth') or {}).get('password')
        for e in taxii_entries
    )
    if not has_collection_creds:
        print('WARNING: TAXII credentials (TAXII_AUTH_USER/TAXII_AUTH_PASSWORD) '
              'are not set — set them in .env (see .env.example). /taxii2/ and '
              'the TAXII-cred data endpoints will reject all clients until then.',
              file=sys.stderr)
_cors_origins = (CONFIG.get('server', {}) or {}).get('cors_origins') or ['*']
CORS(app, origins=_cors_origins)


# ---------------------------------------------------------------------------
# Security hardening: response headers, upload cap, auth-failure throttling
# ---------------------------------------------------------------------------

_SEC_CFG = CONFIG.get('security', {}) or {}

# Cap request bodies. Werkzeug has no default limit, so without this an
# authenticated client can stream an unbounded .csv/.xlsx upload into memory
# (the CSV/Excel import reads the whole body before parsing).
_MAX_UPLOAD_BYTES = int(_SEC_CFG.get('max_upload_bytes', 25 * 1024 * 1024))
_MAX_IMPORT_ROWS = int(_SEC_CFG.get('max_import_rows', 50000))
app.config['MAX_CONTENT_LENGTH'] = _MAX_UPLOAD_BYTES

# Hard ceiling on rows returned by the JSON dashboard endpoint (/objects),
# which the browser loads in one shot. ?limit= narrows it further; the cap
# stops one request from materialising an unbounded JSON payload.
_MAX_OBJECTS_JSON = int(_SEC_CFG.get('max_objects_json', 50000))

# Headers applied to every response. The dashboard is a single self-contained
# inline-script page served from this origin, so 'unsafe-inline' is required
# for script/style; everything else is locked to 'self'.
_SECURITY_HEADERS = (
    ('X-Content-Type-Options', 'nosniff'),
    ('X-Frame-Options', 'DENY'),
    ('Referrer-Policy', 'no-referrer'),
    ('Permissions-Policy', 'geolocation=(), microphone=(), camera=()'),
    ('Strict-Transport-Security', 'max-age=15552000; includeSubDomains'),
    ('Content-Security-Policy',
     "default-src 'self'; script-src 'self' 'unsafe-inline'; "
     "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
     "font-src 'self'; connect-src 'self'; object-src 'none'; "
     "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
)

# Auth-failure throttling. Only requests that actually PRESENT a credential
# are counted (an anonymous probe has no credential to brute-force, and the
# "requires auth" smoke tests send none). A successful request clears the
# counter, so a caller holding correct credentials is never locked out.
_AUTH_FAIL_LIMIT = int(_SEC_CFG.get('auth_fail_limit', 10))
_AUTH_FAIL_WINDOW = int(_SEC_CFG.get('auth_fail_window', 300))
_AUTH_FAIL_MAX_KEYS = 20000
_auth_failures: Dict[str, List[float]] = {}
_auth_fail_lock = threading.Lock()

_THROTTLED_PREFIXES = ('/taxii2', '/objects', '/feed', '/auth', '/ui/login',
                       '/ui/stats', '/ui/collections', '/community',
                       '/subscriptions')


def _parse_trusted_networks(values: Any) -> List[Any]:
    """Parse ``security.trusted_proxies`` entries into ip_network objects."""
    networks: List[Any] = []
    for entry in values or []:
        try:
            networks.append(ipaddress.ip_network(str(entry), strict=False))
        except ValueError:
            logger.warning("Ignoring invalid trusted_proxies entry: %r", entry)
    return networks


# Only trust proxy-supplied client-IP headers when the request actually
# arrives from a trusted proxy. Those headers are caller-controlled otherwise,
# so keying the auth-failure throttle on them would let a client rotate its
# identity and dodge the gate (and, before the eviction fix, reset it for
# everyone). The defaults cover the documented topology — the app is reached
# over loopback or the compose network by the Cloudflare tunnel. Set
# `security.trusted_proxies: []` to trust no proxy and always use the peer
# address.
_TRUSTED_PROXY_NETS = _parse_trusted_networks(
    _SEC_CFG.get('trusted_proxies',
                 ('127.0.0.1/32', '::1/128', '10.0.0.0/8', '172.16.0.0/12',
                  '192.168.0.0/16'))
)


def _proxy_headers_trusted() -> bool:
    """True when the immediate peer is a configured trusted proxy."""
    try:
        peer = ipaddress.ip_address(request.remote_addr or '')
    except ValueError:
        return False
    return any(peer in net for net in _TRUSTED_PROXY_NETS)


def _client_ip() -> str:
    """Best-effort client address, for throttling keys and log lines only.

    Proxy headers (CF-Connecting-IP / X-Forwarded-For) are honoured only when
    the request arrives from a trusted proxy; otherwise the peer address is
    used. These values are never used for authz either way.
    """
    remote = str(request.remote_addr or '')
    if _proxy_headers_trusted():
        raw = (request.headers.get('CF-Connecting-IP')
               or request.headers.get('X-Forwarded-For') or remote)
        return str(raw).split(',')[0].strip()[:64] or 'unknown'
    return remote[:64] or 'unknown'


def _throttle_prefix(path: str) -> Optional[str]:
    """The throttled path class for ``path``, or None when it isn't guarded."""
    p = path or '/'
    for prefix in _THROTTLED_PREFIXES:
        if p == prefix or p.startswith(prefix + '/'):
            return prefix
    return None


def _request_carries_credentials() -> bool:
    return bool(request.headers.get('Authorization')
                or request.headers.get('X-Taxii-Username')
                or request.cookies.get('taxii2_ui_session'))


def _recent_auth_failures(key: str) -> List[float]:
    """Failures for ``key`` inside the window (prunes stale entries)."""
    now = time.time()
    with _auth_fail_lock:
        stamps = [t for t in (_auth_failures.get(key) or [])
                  if now - t < _AUTH_FAIL_WINDOW]
        if stamps:
            _auth_failures[key] = stamps
        else:
            _auth_failures.pop(key, None)
        return stamps


def _record_auth_failure(key: str) -> None:
    """Count one failed authentication for ``key``.

    The table is bounded. At capacity, expired keys are dropped first; if it
    is still full, the least-recently-failed keys are evicted. It is never
    cleared wholesale — a caller able to vary its throttle key would otherwise
    be able to wipe brute-force protection for every other client at once.
    """
    now = time.time()
    with _auth_fail_lock:
        if len(_auth_failures) >= _AUTH_FAIL_MAX_KEYS:
            cutoff = now - _AUTH_FAIL_WINDOW
            for stale in [k for k, v in _auth_failures.items()
                          if not v or v[-1] < cutoff]:
                _auth_failures.pop(stale, None)
        if len(_auth_failures) >= _AUTH_FAIL_MAX_KEYS:
            # Still full of live offenders: evict the oldest ~10%, keeping
            # the most recent (most relevant) offenders throttled.
            overflow = len(_auth_failures) - int(_AUTH_FAIL_MAX_KEYS * 0.9)
            oldest = sorted(_auth_failures,
                            key=lambda k: _auth_failures[k][-1])
            for victim in oldest[:max(overflow, 1)]:
                _auth_failures.pop(victim, None)
        _auth_failures.setdefault(key, []).append(now)


def _too_many_requests_response() -> Response:
    detail = (f'too many failed authentication attempts; '
              f'retry after {_AUTH_FAIL_WINDOW}s')
    if (request.path or '').startswith('/taxii2'):
        resp = _taxii_error(429, 'Too Many Requests', detail, 'throttled')
    else:
        resp = jsonify({'error': detail})
        resp.status_code = 429
    resp.headers['Retry-After'] = str(_AUTH_FAIL_WINDOW)
    return resp


@app.before_request
def _auth_failure_gate():
    """Answer 429 instead of validating credentials for a throttled client."""
    if _AUTH_FAIL_LIMIT <= 0 or _throttle_prefix(request.path) is None:
        return None
    if len(_recent_auth_failures(_client_ip())) >= _AUTH_FAIL_LIMIT:
        logger.warning("Throttling repeated auth failures from %s",
                       _client_ip())
        return _too_many_requests_response()
    return None


@app.after_request
def _security_headers_and_throttle(resp: Response) -> Response:
    for header, value in _SECURITY_HEADERS:
        resp.headers.setdefault(header, value)
    if (_AUTH_FAIL_LIMIT > 0 and _throttle_prefix(request.path) is not None
            and _request_carries_credentials()):
        key = _client_ip()
        if resp.status_code == 401:
            _record_auth_failure(key)
        elif resp.status_code < 400:
            with _auth_fail_lock:
                _auth_failures.pop(key, None)
    return resp


@app.errorhandler(413)
def _request_too_large(_err):
    mb = _MAX_UPLOAD_BYTES / (1024 * 1024)
    return jsonify({
        'error': f'request body too large (limit {mb:.0f} MB)',
    }), 413


# ---------------------------------------------------------------------------
# TAXII 2 Authentication
# ---------------------------------------------------------------------------

def _get_taxii_auth_config() -> Dict[str, str]:
    """Legacy override credentials (app.config overridable in tests).

    This is the old single-credential model: tests (and old configs) set
    app.config['TAXII_AUTH'] and expect every endpoint to accept it. It is
    treated as a *global* principal: valid anywhere, reads every collection.
    """
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


def _credentials_match(user: str, password: str, cfg: Dict[str, Any]) -> bool:
    """Constant-time comparison against a configured username/password pair."""
    expected_user = str((cfg or {}).get('username') or '')
    expected_pass = str((cfg or {}).get('password') or '')
    if not expected_user or not expected_pass:
        return False
    return (hmac.compare_digest(str(user or ''), expected_user)
            and hmac.compare_digest(str(password or ''), expected_pass))


# ---------------------------------------------------------------------------
# Scoped API keys (dashboard-generated consumer credentials)
# ---------------------------------------------------------------------------
# A key is an alternative to a per-collection username/password: it is
# generated in the dashboard, scoped to one or more collections, optionally
# time-limited and rate-limited. Vision One only speaks HTTP Basic, so the
# key rides in the *password* position (`curl -u <prefix>:<key>` and the
# X-Taxii-* headers work too, since _request_taxii_credentials accepts both).
#
# Only the O(1) lookup `prefix` and a SHA-256 of the secret are stored; the
# plaintext is returned exactly once, at creation, and never logged.

_API_KEY_PREFIX_TAG = 'taxii_'
_API_KEY_PREFIX_LEN = 8          # hex chars after the 'taxii_' tag
_API_KEY_SECRET_BYTES = 24       # -> 32 url-safe chars


def _hash_api_key_secret(secret: str) -> str:
    """SHA-256 (hex) of a key's secret.

    Deliberately a fast hash: the secret is high-entropy random (not a
    user-chosen password), so there is nothing to brute-force, and this runs
    on every TAXII poll. Adaptive KDFs (``generate_password_hash``) are for
    low-entropy secrets and would burn CPU on every request here.
    """
    return hashlib.sha256(str(secret).encode('utf-8')).hexdigest()


def _generate_api_key() -> Tuple[str, str, str]:
    """Mint a key: returns ``(plaintext, prefix, secret_hash)``."""
    prefix = secrets.token_hex(_API_KEY_PREFIX_LEN // 2)
    secret = secrets.token_urlsafe(_API_KEY_SECRET_BYTES)
    plaintext = f'{_API_KEY_PREFIX_TAG}{prefix}_{secret}'
    return plaintext, prefix, _hash_api_key_secret(plaintext)


def _split_api_key(key: str) -> Optional[Tuple[str, str]]:
    """``(prefix, full_key)`` for a well-formed key, else None."""
    if not isinstance(key, str) or not key.startswith(_API_KEY_PREFIX_TAG):
        return None
    parts = key.split('_', 2)
    if len(parts) != 3 or len(parts[1]) != _API_KEY_PREFIX_LEN or not parts[2]:
        return None
    return parts[1], key


def _parse_key_collections(raw: Any) -> List[str]:
    """Decode the stored JSON scope, tolerating a malformed/legacy value."""
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return []
    if not isinstance(value, list):
        return []
    return [str(v) for v in value if str(v or '').strip()]


def _all_key_object_types() -> List[str]:
    """The full sorted list of stored object types a key may be scoped to.

    Sourced from ``_SUPPORTED_STIX_TYPES`` — everything the feed stores — so the
    strict allow-list can express any type, not just IOCs.
    """
    return sorted(_SUPPORTED_STIX_TYPES)


def _parse_key_object_types(raw: Any) -> List[str]:
    """Decode a key's object-type allow-list (JSON list).

    Mirrors :func:`_parse_key_collections`, but never returns an empty list: a
    falsy/malformed/empty value falls back to ALL types, so a legacy or corrupt
    row can never silently lock a live consumer out of the feed.
    """
    if not raw:
        return _all_key_object_types()
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return _all_key_object_types()
    if not isinstance(value, list):
        return _all_key_object_types()
    parsed = [str(v) for v in value if str(v or '').strip()
              and str(v) in _SUPPORTED_STIX_TYPES]
    # De-dupe, preserving order.
    seen: List[str] = []
    for t in parsed:
        if t not in seen:
            seen.append(t)
    return seen or _all_key_object_types()


def _api_key_row(password: str) -> Optional[Dict[str, Any]]:
    """Resolve a live (well-formed, enabled, unexpired) key to its scope.

    Returns a plain dict so the caller holds no ORM object once the session
    closes, or None for anything that is not a currently-valid key.
    """
    split = _split_api_key(password)
    if split is None:
        return None
    prefix, key = split
    session = create_session()
    try:
        row = session.query(ApiKey).filter_by(prefix=prefix).first()
        if row is None or not row.enabled:
            return None
        if not hmac.compare_digest(str(row.secret_hash or ''),
                                   _hash_api_key_secret(key)):
            return None
        now = datetime.utcnow()
        if row.expires_at is not None and row.expires_at <= now:
            return None
        info = {
            'id': row.id,
            'label': row.label,
            'prefix': row.prefix,
            'collections': _parse_key_collections(row.collections),
            'types': _parse_key_object_types(row.types),
            'rate_limit': int(row.rate_limit or 0),
            'rate_window': int(row.rate_window or 0),
            'max_objects': int(row.max_objects or 0),
        }
        # Touch last_used_at at most once a minute: it is dashboard
        # information, not an audit trail, and a write per poll is waste.
        if row.last_used_at is None or (now - row.last_used_at).total_seconds() >= 60:
            row.last_used_at = now
            session.commit()
        return info
    except Exception as exc:  # pragma: no cover - depends on DB availability
        logger.error("API key lookup failed: %s", exc)
        return None
    finally:
        session.close()


def _api_key_for(client_pass: str) -> Optional[Dict[str, Any]]:
    """The API key a presented password names, memoised per request.

    Resolution hits the DB (and compares a hash), so it is cached on Flask's
    ``g``: the auth seams below are called several times per request.
    """
    password = str(client_pass or '')
    if not password.startswith(_API_KEY_PREFIX_TAG):
        return None
    try:
        cache = getattr(g, '_taxii_api_keys', None)
        if cache is None:
            cache = {}
            g._taxii_api_keys = cache
    except RuntimeError:
        # No request/app context (direct call from a script or unit test).
        return _api_key_row(password)
    if password not in cache:
        cache[password] = _api_key_row(password)
    return cache[password]


_API_KEY_HITS_MAX_KEYS = 20000
_api_key_hits: Dict[str, List[float]] = {}
_api_key_hits_lock = threading.Lock()


def _api_key_rate_limited(key: Dict[str, Any]) -> Optional[int]:
    """Sliding-window rate limit for one key.

    Returns the ``Retry-After`` seconds when this request is over the key's
    limit, or None when it may proceed. In-memory and per-process — the same
    caveat as the auth-failure throttle: counters reset on restart and would
    need a shared store (Redis) to hold across workers. The server is
    deliberately single-process (waitress), so one table is the whole picture.
    """
    limit = int(key.get('rate_limit') or 0)
    if limit <= 0:
        return None
    window = max(1, int(key.get('rate_window') or 60))
    ident = str(key.get('id') or '')
    now = time.time()
    with _api_key_hits_lock:
        hits = [t for t in (_api_key_hits.get(ident) or []) if now - t < window]
        if len(hits) >= limit:
            _api_key_hits[ident] = hits
            return max(1, int(round(window - (now - hits[0]))))
        hits.append(now)
        if ident not in _api_key_hits and len(_api_key_hits) >= _API_KEY_HITS_MAX_KEYS:
            # Bound the table: drop keys with nothing left in their window.
            for stale in [k for k, v in _api_key_hits.items()
                          if not v or now - v[-1] >= window]:
                _api_key_hits.pop(stale, None)
        _api_key_hits[ident] = hits
    return None


def _too_many_key_requests_response(retry_after: int) -> Response:
    detail = f'API key rate limit exceeded; retry after {retry_after}s'
    if (request.path or '').startswith('/taxii2'):
        resp = _taxii_error(429, 'Too Many Requests', detail, 'throttled')
    else:
        resp = jsonify({'error': detail})
        resp.status_code = 429
    resp.headers['Retry-After'] = str(retry_after)
    return resp


@app.before_request
def _api_key_rate_gate():
    """Enforce a key's own sliding window (429 + Retry-After once past it).

    Runs before the credential checks, but only for a *well-formed, live*
    key: an unknown or revoked key falls through to the normal 401 path and
    is covered by the per-IP auth-failure throttle instead.
    """
    if _throttle_prefix(request.path) is None:
        return None
    _user, password = _request_taxii_credentials()
    key = _api_key_for(password)
    if key is None:
        return None
    retry_after = _api_key_rate_limited(key)
    if retry_after is None:
        return None
    logger.warning("Rate-limited API key %s (%s request(s) per %ss)",
                   key.get('prefix'), key.get('rate_limit'),
                   key.get('rate_window'))
    return _too_many_key_requests_response(retry_after)


def _validate_taxii_auth(client_user: str, client_pass: str) -> bool:
    """Validate TAXII 2 authentication credentials.

    True when the credentials match ANY configured collection, the
    legacy/test override (which can read every collection), or a live API key.
    """
    override = _get_taxii_auth_config()
    if override.get('username'):
        if _credentials_match(client_user, client_pass, override):
            return True
    if any(
        _credentials_match(client_user, client_pass,
                           {'username': c.username, 'password': c.password})
        for c in TAXII_COLLECTIONS
    ):
        return True
    return _api_key_for(client_pass) is not None


def _collections_readable_by(client_user: str, client_pass: str
                             ) -> 'List[CollectionConfig]':
    """Collections a principal (TAXII credentials) may read.

    The legacy/test override is a global principal: it reads every
    collection. An API key reads exactly the collections in its scope.
    Otherwise a principal reads exactly the collection(s) whose configured
    username/password match its credentials.
    """
    key = _api_key_for(client_pass)
    if key is not None:
        scope = set(key['collections'])
        return [c for c in TAXII_COLLECTIONS if c.id in scope]
    override = _get_taxii_auth_config()
    if override.get('username'):
        if _credentials_match(client_user, client_pass, override):
            return list(TAXII_COLLECTIONS)
    return [
        c for c in TAXII_COLLECTIONS
        if _credentials_match(client_user, client_pass,
                              {'username': c.username, 'password': c.password})
    ]


# ---------------------------------------------------------------------------
# Web UI session auth (separate from TAXII credentials)
# ---------------------------------------------------------------------------

UI_CFG = CONFIG.get('ui', {}) or {}
UI_AUTH = UI_CFG.get('auth', {}) or {}
_ui_username = str(UI_AUTH.get('username') or '')
_ui_password = str(UI_AUTH.get('password') or '')
if not _ui_username or not _ui_password:
    print('WARNING: UI credentials (UI_AUTH_USER/UI_AUTH_PASSWORD) are not '
          'set — set them in .env (see .env.example). The dashboard login '
          'will reject all users until then.', file=sys.stderr)
_ui_secret = str(CONFIG.get('security', {}).get('secret_key', 'dev-secret-key-change-in-production'))
_ui_session_ttl = int(UI_CFG.get('session_ttl', 43200))  # seconds (default 12 h)

from itsdangerous import BadSignature, URLSafeTimedSerializer

_session_serializer = URLSafeTimedSerializer(_ui_secret, salt='taxii2-ui-session')


# Dashboard roles, weakest to strongest. A principal may do anything at its
# own level or below:
#   viewer — read the dashboard (feed, graph, sources, stats)
#   editor — viewer + data mutations (ingest, import, delete, revoke, purge,
#            community pulls)
#   admin  — editor + API-key and user management
ROLE_LEVELS = {'viewer': 1, 'editor': 2, 'admin': 3}
DEFAULT_ROLE = 'viewer'
_PRINCIPAL_UNSET = object()


def _role_at_least(role: Any, minimum: str) -> bool:
    """True when ``role`` ranks at or above ``minimum``."""
    return ROLE_LEVELS.get(str(role or ''), 0) >= ROLE_LEVELS.get(minimum, 99)


def _session_cookie(username: str, source: str = 'user') -> str:
    """Create a signed, time-bounded session cookie for the web UI.

    ``source`` records HOW the session was established, because that decides
    how the principal is re-resolved on later requests:
      * ``user``   — a ``ui_users`` row, re-checked every request, so
                     disabling the account or changing its role applies at once
      * ``static`` — the break-glass ``ui.auth`` pair (always admin)
      * ``sso``    — an SSO identity with no local row (role from config)
    """
    return _session_serializer.dumps({'user': username, 'src': source})


def _session_payload() -> Optional[Dict[str, str]]:
    """Decode the session cookie to ``{'user', 'src'}``, or None."""
    token = request.cookies.get('taxii2_ui_session')
    if not token:
        return None
    try:
        payload = _session_serializer.loads(token, max_age=_ui_session_ttl)
    except BadSignature:
        return None
    if not isinstance(payload, dict) or not payload.get('user'):
        return None
    return {'user': str(payload['user']),
            'src': str(payload.get('src') or 'user')}


def _session_user() -> Optional[str]:
    """Decode the session cookie; returns the username or None."""
    payload = _session_payload()
    return payload['user'] if payload else None


def _lookup_ui_user(username: str) -> Optional[Dict[str, Any]]:
    """The ENABLED dashboard user named ``username``, or None."""
    session = create_session()
    try:
        row = session.query(UIUser).filter_by(username=str(username or '')).first()
        if row is None or not row.enabled:
            return None
        return {'id': row.id, 'user': row.username,
                'role': str(row.role or DEFAULT_ROLE)}
    finally:
        session.close()


def _any_ui_users() -> bool:
    """True when at least one dashboard user exists in ``ui_users``."""
    session = create_session()
    try:
        return session.query(UIUser).first() is not None
    finally:
        session.close()


def _resolve_principal() -> Optional[Dict[str, Any]]:
    """Resolve the dashboard principal for this request, or None."""
    payload = _session_payload()
    if payload:
        src = payload['src']
        if src == 'static':
            return {'user': payload['user'], 'role': 'admin', 'via': 'ui_auth'}
        if src == 'sso':
            return {'user': payload['user'],
                    'role': SSO_DEFAULT_ROLE, 'via': 'sso'}
        row = _lookup_ui_user(payload['user'])
        # A local session whose user was deleted or disabled stops working at
        # once, without waiting for the cookie to expire.
        if row is None:
            return None
        return {'user': row['user'], 'role': row['role'], 'via': 'session'}
    user, pw = _request_taxii_credentials()
    if _validate_ui_credentials(user, pw):
        # Break-glass: the static pair is never stored in ui_users, so a bad
        # role edit can't lock the operator out.
        return {'user': user, 'role': 'admin', 'via': 'ui_auth'}
    admin = _get_admin_auth_config()
    if admin.get('username') and _credentials_match(user, pw, admin):
        return {'user': user, 'role': 'admin', 'via': 'admin_auth'}
    return None


def _principal() -> Optional[Dict[str, Any]]:
    """The dashboard principal for this request, or None (memoised per request).

    Memoised on ``g``: several endpoints consult it more than once, and a
    ``ui_users`` lookup per call would be wasteful.
    """
    try:
        cached = getattr(g, '_ui_principal', _PRINCIPAL_UNSET)
    except RuntimeError:            # no request context (tests, scripts)
        cached = _PRINCIPAL_UNSET
    if cached is not _PRINCIPAL_UNSET:
        return cached
    principal = _resolve_principal()
    try:
        g._ui_principal = principal
    except RuntimeError:
        pass
    return principal


def _require_role(minimum: str) -> bool:
    """True when the request carries a dashboard principal of ``minimum`` role."""
    principal = _principal()
    return bool(principal) and _role_at_least(principal['role'], minimum)


def _actor() -> str:
    """Who is acting, for audit lines: ``user (role via source) from ip``."""
    principal = _principal()
    if not principal:
        return f'anonymous from {_client_ip()}'
    return (f"{principal['user']} ({principal['role']} via {principal['via']}) "
            f"from {_client_ip()}")


def _audit(action: str, *, target: Optional[str] = None,
           detail: Optional[str] = None, collection: Optional[str] = None,
           count: Optional[int] = None, actor: Optional[str] = None,
           role: Optional[str] = None, via: Optional[str] = None) -> None:
    """Append one row to the audit trail. NEVER raises into the request.

    Best-effort observability: any failure is logged and swallowed, because a
    broken audit write must not turn a successful mutation into a 500. Identity
    comes from :func:`_principal` + :func:`_client_ip` (both memoised, so no
    extra DB work), unless ``actor``/``role``/``via`` are passed explicitly —
    the login event needs that, since the principal does not exist yet on the
    request that creates the session.

    Uses its OWN short-lived session (independent of the endpoint's), so it is
    safe to call after that session has closed. Text fields are truncated
    defensively; secrets must never be passed in.
    """
    if not AUDIT_ENABLED:
        return
    try:
        if actor is None:
            principal = _principal()
            if principal:
                actor = str(principal['user'])
                role = role if role is not None else str(principal.get('role') or '')
                via = via if via is not None else str(principal.get('via') or '')
            else:
                actor = 'anonymous'
        row = AuditEvent(
            id=uuid.uuid4().hex,
            actor=(str(actor) or 'anonymous')[:_AUDIT_TARGET_MAX],
            role=(str(role)[:_AUDIT_TARGET_MAX] if role else None),
            via=(str(via)[:_AUDIT_TARGET_MAX] if via else None),
            ip=_client_ip(),
            action=str(action)[:_AUDIT_TARGET_MAX],
            target=(str(target)[:_AUDIT_TARGET_MAX] if target else None),
            collection=(str(collection)[:_AUDIT_TARGET_MAX] if collection else None),
            count=(int(count) if count is not None else None),
            detail=(str(detail)[:_AUDIT_DETAIL_MAX] if detail else None),
        )
        session = create_session()
        try:
            session.add(row)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    except Exception as exc:  # pragma: no cover - audit must never break a request
        logger.warning("Audit write failed for action %r: %s", action, exc)


def _ui_session_valid() -> bool:
    return _principal() is not None


def _check_ui_login(username: str, password: str) -> Optional[Dict[str, str]]:
    """Verify a dashboard login against ``ui_users``, then the static pair.

    Returns ``{'user', 'role', 'src'}`` or None. A matching row wins; the
    static ``ui.auth`` credential is accepted as a break-glass admin so an
    existing deployment can always get in.
    """
    session = create_session()
    try:
        row = session.query(UIUser).filter_by(username=str(username or '')).first()
        if (row is not None and row.enabled and row.password_hash
                and check_password_hash(row.password_hash, str(password or ''))):
            row.last_login_at = datetime.utcnow()
            session.commit()
            return {'user': row.username,
                    'role': str(row.role or DEFAULT_ROLE), 'src': 'user'}
    finally:
        session.close()
    if _validate_ui_credentials(username, password):
        return {'user': username, 'role': 'admin', 'src': 'static'}
    return None


def _request_allowed() -> bool:
    """Data endpoints accept TAXII credentials (scripts / Vision One,
    unchanged) OR a valid web-UI session cookie (browser)."""
    if _ui_session_valid():
        return True
    user, pw = _request_taxii_credentials()
    return _validate_taxii_auth(user, pw) or _validate_ui_credentials(user, pw)


def _validate_ui_credentials(user: str, password: str) -> bool:
    """Constant-time check of the static dashboard credentials (ui.auth)."""
    return _credentials_match(user, password,
                              {'username': _ui_username,
                               'password': _ui_password})


def _get_admin_auth_config() -> Dict[str, str]:
    """Optional feed-wide admin principal (``taxii.admin_auth``).

    When it is not configured, feed-wide writes are limited to the dashboard
    session and the UI credentials.
    """
    override = app.config.get('TAXII_ADMIN_AUTH')
    cfg = override if override is not None else (
        (CONFIG.get('taxii', {}) or {}).get('admin_auth') or {})
    return {
        'username': str((cfg or {}).get('username') or ''),
        'password': str((cfg or {}).get('password') or ''),
    }


def _write_allowed() -> bool:
    """Authorization for data-mutating endpoints (``editor`` or above).

    Only a dashboard principal of at least ``editor`` rank may write. TAXII
    credentials — including the read credential handed to a consumer such as
    Vision One — are read-only, so a leaked consumer credential cannot ingest,
    revoke, delete or purge anything.
    """
    return _require_role('editor')


def _admin_allowed() -> bool:
    """Authorization for credential/user management (``admin`` only).

    Minting an API key or creating a user *grants* access, so it sits a level
    above the data mutations ``_write_allowed`` guards.
    """
    return _require_role('admin')


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
# SSO identities have no row in `ui_users` (they are managed by the IdP), so
# they need a role from config. Defaults to the weakest role: an SSO user is
# *authenticated* by the tenant, but that alone should not confer write access
# to the feed.
SSO_DEFAULT_ROLE = str(SSO_CFG.get('default_role') or DEFAULT_ROLE)
if SSO_DEFAULT_ROLE not in ROLE_LEVELS:
    logger.warning("sso.default_role %r is not one of %s; using %r",
                   SSO_DEFAULT_ROLE, sorted(ROLE_LEVELS), DEFAULT_ROLE)
    SSO_DEFAULT_ROLE = DEFAULT_ROLE
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
        max_age=600, httponly=True, samesite='Lax', secure=True,
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
        'taxii2_ui_session', _session_cookie(username, 'sso'),
        max_age=_ui_session_ttl, httponly=True, samesite='Lax', secure=True,
    )
    resp.delete_cookie(_oauth_state_cookie, httponly=True, samesite='Lax',
                       secure=True)
    logger.info("SSO login successful for %s (role=%s)", username,
                SSO_DEFAULT_ROLE)
    _audit('auth.login', target=username, actor=username,
           role=SSO_DEFAULT_ROLE, via='sso', detail='sso')
    return resp


def _ui_sso_fail(message: str) -> Response:
    """Render a small inline error and point back at the login form."""
    # ``message`` can embed caller-controlled query parameters (?error=...),
    # so it is HTML-escaped rather than interpolated raw.
    resp = make_response(
        f'<!doctype html><meta charset="utf-8">'
        f'<title>Sign-in failed</title><body style="font-family:system-ui;max-width:520px;'
        f'margin:80px auto;padding:0 16px"><h2>Sign-in failed</h2>'
        f'<p>{html.escape(message)}</p><p><a href="/">Return to login</a></p></body>',
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

# STIX 2.1 object types this server can store and serve. The classic IOC
# types (ipv4-addr / domain-name / file-hash / indicator) are joined by
# extra single-value SCOs (url, email-addr, ipv6-addr, mac-addr,
# windows-registry-key, autonomous-system), the SDOs the UI feeds
# (malware / threat-actor / campaign), the SDOs community TAXII feeds carry
# (report / identity / attack-pattern / vulnerability), and STIX
# relationships (the graph).
_SUPPORTED_STIX_TYPES = frozenset({
    'ipv4-addr', 'domain-name', 'file-hash', 'indicator',
    'url', 'email-addr', 'ipv6-addr', 'mac-addr',
    'windows-registry-key', 'autonomous-system',
    'malware', 'malware-family', 'threat-actor', 'campaign', 'relationship',
    'report', 'identity', 'attack-pattern', 'vulnerability',
})


def _validate_stix_object(obj: Any) -> Optional[str]:
    """Validate an ingest payload; returns a warning string or None (valid).

    Loose by design — community pullers and the web UI generate these, and
    a bad row must not block the batch: the caller skips the object and
    logs the warning instead. Checks id/type shape and prefix consistency,
    a supported type, integer confidence in [0, 100], list-shaped labels,
    and parseable created/modified timestamps.
    """
    if not isinstance(obj, dict):
        return 'not an object'
    stix_id = obj.get('id')
    obj_type = obj.get('type')
    if not isinstance(stix_id, str) or not stix_id:
        return 'missing/empty id'
    if not isinstance(obj_type, str) or not obj_type:
        return 'missing/empty type'
    if obj_type not in _SUPPORTED_STIX_TYPES:
        return f'unsupported type {obj_type!r}'
    if not re.fullmatch(r'[A-Za-z0-9\-]+--[A-Za-z0-9\-]+', stix_id):
        return f'bad STIX id shape {stix_id!r} (expected <type>--<value>)'
    if not stix_id.startswith(obj_type + '--'):
        return (f'id prefix {stix_id.split("--", 1)[0]!r} '
                f'does not match type {obj_type!r}')
    confidence = obj.get('confidence')
    if confidence is not None:
        try:
            if not 0 <= int(confidence) <= 100:
                return f'confidence out of range: {confidence}'
        except (TypeError, ValueError):
            return f'confidence not an integer: {confidence!r}'
    labels = obj.get('labels')
    if labels is not None and not isinstance(labels, list):
        return 'labels must be a list'
    if obj_type == 'relationship':
        od = obj.get('object') or {}
        nested = od.get('relationship') if isinstance(od, dict) else None
        inner = nested if isinstance(nested, dict) else od
        for field in ('source_ref', 'relationship_type', 'target_ref'):
            if not inner.get(field):
                return f'relationship missing {field!r}'
    if obj_type == 'report':
        od = obj.get('object') or {}
        nested = od.get('report') if isinstance(od, dict) else None
        inner = nested if isinstance(nested, dict) else od
        if not inner.get('object_refs'):
            return 'report missing object_refs'
    for key in ('created', 'modified'):
        if obj.get(key) is not None and _parse_iso_ts(obj.get(key)) is None:
            return f'{key} not parseable: {obj.get(key)!r}'
    return None


def _extract_object_fields(
    obj_type: str, object_dict: Any
) -> Dict[str, Optional[str]]:
    """Extract typed values from an ingested STIX object payload.

    Accepts both flat ({"value": ...}) and type-nested
    ({"ipv4-addr": {"value": ...}}) payload shapes, plus the
    relationship fields (source_ref / target_ref / relationship_type).
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
        'value': None,
        'source_ref': None,
        'target_ref': None,
        'relationship_type': None,
        'object_refs': None,
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
    elif obj_type in ('url', 'email-addr', 'ipv6-addr', 'mac-addr'):
        result['value'] = inner.get('value')
    elif obj_type == 'windows-registry-key':
        # STIX uses `key` for registry keys; accept value as a fallback.
        result['value'] = inner.get('key') or inner.get('value')
    elif obj_type == 'autonomous-system':
        num = inner.get('number')
        result['value'] = str(num) if num is not None else inner.get('value')
    elif obj_type == 'relationship':
        result['source_ref'] = inner.get('source_ref')
        result['relationship_type'] = inner.get('relationship_type')
        result['target_ref'] = inner.get('target_ref')
    elif obj_type == 'report':
        result['name'] = inner.get('name')
        refs = inner.get('object_refs')
        if isinstance(refs, list):
            result['object_refs'] = json.dumps([str(r) for r in refs])
    elif obj_type in ('identity', 'attack-pattern', 'vulnerability'):
        result['name'] = inner.get('name')
    elif obj_type in ('indicator', 'malware', 'malware-family',
                      'threat-actor', 'campaign'):
        result['name'] = inner.get('value') or inner.get('name')
    return result


def ingest_objects(stix_objects: List[Dict[str, Any]], mode: str = 'replace',
                   source: str = 'manual',
                   collection: Optional[str] = None,
                   scores: Optional[Dict[str, Tuple[int, Dict[str, int]]]] = None
                   ) -> int:
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
    web-UI/API ingest, ``'otx'`` for the OTX puller, ...). ``collection`` is
    the TAXII collection the objects belong to; when omitted it resolves to
    the manual collection (``gt_intel``) — never to the primary collection,
    which may be the aggregate and owns no rows of its own.

    Objects failing :func:`_validate_stix_object` are skipped with a warning
    (never blocking the batch). Returns the number of objects stored in the
    mode-specific batch. Raises on failure.
    """
    if not collection:
        collection = DEFAULT_MANUAL_COLLECTION_ID
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
                # Replace: wipe only the manual feed OF THIS COLLECTION;
                # community-sourced rows and other collections survive so a
                # UI save cannot delete pulled intel or a sibling collection.
                preserved_revoked = {
                    r.stix_id: bool(r.revoked)
                    for r in session.query(STIXObject.stix_id, STIXObject.revoked).filter_by(
                        source=source, collection_id=collection
                    ).all()
                }
                session.query(STIXObject).filter_by(
                    source=source, collection_id=collection
                ).delete()
                for s in [s for s in memory_store
                          if memory_store[s].source == source
                          and memory_store[s].collection == collection]:
                    memory_store.pop(s, None)
                session.flush()
                existing = {}

            count = 0
            for obj_dict in stix_objects:
                warn = _validate_stix_object(obj_dict)
                if warn:
                    logger.warning("Skipping invalid STIX object: %s", warn)
                    continue
                stix_id = obj_dict.get('id')
                obj_type = obj_dict.get('type')

                object_dict = obj_dict.get('object') or {}
                labels = obj_dict.get('labels') or []
                if not isinstance(labels, list):
                    labels = [labels]
                confidence = int(obj_dict.get('confidence', 0) or 0)
                fields = _extract_object_fields(obj_type, object_dict)
                # Upstream valid_from (fall back to upstream created), kept so
                # served indicators carry the source's validity start.
                valid_from = _parse_iso_naive(
                    obj_dict.get('valid_from') or object_dict.get('valid_from')
                    or obj_dict.get('created') or object_dict.get('created')
                )

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

                # Scoring pipeline: the caller (a poller, via route_by_score)
                # hands us the computed score keyed by stix id. Absent = this
                # object was not scored, which stays NULL rather than 0 — see
                # the STIXObject.score comment.
                scored = (scores or {}).get(stix_id)
                score_value: Optional[int] = None
                score_json: Optional[str] = None
                if scored is not None:
                    score_value = int(scored[0])
                    score_json = json.dumps(scored[1], sort_keys=True)

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
                    value=fields['value'],
                    source_ref=fields['source_ref'],
                    target_ref=fields['target_ref'],
                    relationship_type=fields['relationship_type'],
                    object_refs=fields['object_refs'],
                    valid_from=valid_from,
                    collection=collection,
                    source=source,
                    revoked=revoked,
                    # `created` is immutable per object; a merge refresh keeps
                    # the original and only moves `modified` (mirrors the row,
                    # whose `modified` has onupdate=utcnow).
                    created=(existing_row.created if existing_row is not None
                             else now),
                    modified=now,
                    score=score_value,
                    score_breakdown=score_json,
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
                    row.value = fields['value']
                    row.source_ref = fields['source_ref']
                    row.target_ref = fields['target_ref']
                    row.relationship_type = fields['relationship_type']
                    row.object_refs = fields['object_refs']
                    row.valid_from = valid_from
                    row.collection_id = collection
                    row.last_seen = now
                    row.revoked = revoked  # sticky (see above); keeps first revoked_at
                    # A re-score supersedes the stored one; when this object was
                    # not scored on this pass, keep whatever is already there.
                    if scored is not None:
                        row.score = score_value
                        row.score_breakdown = score_json
                        row.scored_at = now
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
                        value=fields['value'],
                        source_ref=fields['source_ref'],
                        target_ref=fields['target_ref'],
                        relationship_type=fields['relationship_type'],
                        object_refs=fields['object_refs'],
                        valid_from=valid_from,
                        collection_id=collection,
                        source=source,
                        first_seen=now,
                        last_seen=now,
                        revoked=revoked,
                        revoked_at=now if revoked else None,
                        score=score_value,
                        score_breakdown=score_json,
                        scored_at=now if scored is not None else None,
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


def purge_all(collection: Optional[str] = None) -> int:
    """Purge threat intelligence data (memory + DB).

    With ``collection=None`` wipes EVERYTHING (all collections, all
    sources). With a collection id, wipes only that collection's objects —
    and for an *aggregate*, the union of its members. The aggregate is the
    primary collection (what the dashboard's "Purge all" targets by default),
    so rejecting it here would silently turn that button into a no-op;
    unlike ``collection=None`` it still spares non-member collections.
    Returns the number of rows purged.
    """
    ids = _collection_ids_for(collection)
    session = create_session()
    try:
        with memory_lock:
            if ids:
                rows = session.query(STIXObject).filter(
                    STIXObject.collection_id.in_(ids)).all()
                for s in [s for s in memory_store
                          if memory_store[s].collection in ids]:
                    memory_store.pop(s, None)
            else:
                rows = session.query(STIXObject).all()
                memory_store.clear()
            for r in rows:
                session.delete(r)
            session.commit()
            return len(rows)
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
# TAXII 2.1 API root, collections of STIX 2.1 JSON objects, and a
# subscriptions stub — the same surface Vision One polls from OTX.
#
# Collections: the legacy single-collection keys (`collection_id` +
# `auth`) still work. To serve more than one consumer with separate
# credentials, list them under `taxii.collections:` — each entry is a
# collection with its OWN HTTP Basic credentials, so a client can only see
# and read the collections its credentials authorize (per-client RBAC).

TAXII_CFG = CONFIG.get('taxii', {}) or {}
DEFAULT_COLLECTION_ID = 'threat-intel'
# Get Objects response shape:
#   'bundle' (default) — OTX-compatible: the STIX bundle at the top level with
#                        more/next, no envelope. What Vision One ingests.
#   'envelope'         — the TAXII 2.1 Message Resource (spec §5.3).
TAXII_OBJECTS_SHAPE = str(TAXII_CFG.get('objects_shape') or 'bundle').lower()


def _default_page_cap() -> Optional[int]:
    """Page ceiling for a Get Objects request that passes no ``limit``.

    Bounds an otherwise unbounded query/materialise; clients page on with
    ``more``/``next``. ``taxii.max_objects: 0`` disables the cap.
    """
    try:
        cap = int(TAXII_CFG.get('max_objects') or 0)
    except (TypeError, ValueError):
        return None
    return cap if cap > 0 else None


@dataclass
class CollectionConfig:
    """One TAXII collection: identity + the credentials that may read it.

    ``members`` turns a collection into an *aggregate*: a virtual collection
    that serves the union of its members' objects and owns no rows of its
    own. Aggregates are flat (a member is never itself an aggregate) and
    read-only — writes name a member.
    """
    id: str
    title: str
    description: str
    username: str
    password: str
    members: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.id = str(self.id or DEFAULT_COLLECTION_ID)
        self.title = str(self.title or self.id)
        self.description = str(self.description or '')
        self.username = str(self.username or '')
        self.password = str(self.password or '')
        # Normalise members: coerce to str, drop blanks, dedupe preserving
        # order, and drop a self-reference (an id nothing is ever stored
        # under, which would be a silent no-op in the union).
        seen = set()
        normalised: List[str] = []
        for member in self.members or []:
            mid = str(member or '').strip()
            if not mid or mid == self.id or mid in seen:
                continue
            seen.add(mid)
            normalised.append(mid)
        self.members = normalised

    @property
    def is_aggregate(self) -> bool:
        """True when this collection serves the union of its members."""
        return bool(self.members)


def _build_collection_configs(taxii_cfg: Dict[str, Any]) -> List[CollectionConfig]:
    """Parse the TAXII collection registry from config.

    ``taxii.collections:`` (a list) wins when present; otherwise the legacy
    single-collection keys (``collection_id`` / ``collection_title`` /
    ``auth``) build one collection, so existing configs behave unchanged.
    """
    entries = taxii_cfg.get('collections')
    if isinstance(entries, list) and entries:
        cfgs: List[CollectionConfig] = []
        for e in entries:
            if not isinstance(e, dict) or not e.get('id'):
                continue
            auth = e.get('auth') or {}
            members = e.get('members')
            cfgs.append(CollectionConfig(
                id=str(e['id']),
                title=str(e.get('title') or ''),
                description=str(e.get('description') or ''),
                username=str(auth.get('username') or ''),
                password=str(auth.get('password') or ''),
                members=list(members) if isinstance(members, (list, tuple)) else [],
            ))
        return cfgs or _build_collection_configs({})
    # Legacy single-collection form: no members, so this path is unchanged.
    auth = taxii_cfg.get('auth') or {}
    return [CollectionConfig(
        id=str(taxii_cfg.get('collection_id') or DEFAULT_COLLECTION_ID),
        title=str(taxii_cfg.get('collection_title') or 'Custom Threat Intelligence Feed'),
        description=(
            'Custom threat intelligence objects: IPv4/IPv6 addresses, domain '
            'names, file hashes, URLs, and indicators.'
        ),
        username=str(auth.get('username') or ''),
        password=str(auth.get('password') or ''),
    )]


TAXII_COLLECTIONS: List[CollectionConfig] = _build_collection_configs(TAXII_CFG)
TAXII_COLLECTION_MAP: Dict[str, CollectionConfig] = {
    c.id: c for c in TAXII_COLLECTIONS
}
# The primary collection: legacy single-collection id (kept for back-compat),
# or the first configured collection.
TAXII_COLLECTION_ID = TAXII_COLLECTIONS[0].id if TAXII_COLLECTIONS else DEFAULT_COLLECTION_ID
TAXII_COLLECTION_TITLE = (
    TAXII_COLLECTIONS[0].title if TAXII_COLLECTIONS else 'Custom Threat Intelligence Feed'
)


def _validate_collection_members() -> None:
    """Drop unknown / nested members; refuse an aggregate left with none.

    A member must name another *leaf* collection. Nested aggregates are
    dropped rather than expanded, so the union stays a flat one-level fact
    with no recursion, cycle detection or ordering ambiguity. Membership is
    pruned in place, which is why this runs once, right after the registry is
    built.

    An aggregate with zero members is the one misconfiguration that makes a
    feed look silently empty, so it raises at startup instead of serving
    nothing.
    """
    for cfg in TAXII_COLLECTIONS:
        if not cfg.members:
            continue
        kept: List[str] = []
        for mid in cfg.members:
            member = TAXII_COLLECTION_MAP.get(mid)
            if member is None:
                logger.warning(
                    "Collection %r: dropping unknown member %r", cfg.id, mid)
                continue
            if member.members:
                logger.warning(
                    "Collection %r: dropping nested aggregate member %r "
                    "(aggregates are flat)", cfg.id, mid)
                continue
            kept.append(mid)
        cfg.members = kept
        if not cfg.members:
            raise ValueError(
                f"taxii.collections: {cfg.id!r} is an aggregate whose members "
                f"are all unknown or are themselves aggregates — it would "
                f"serve an empty feed. Name at least one leaf collection."
            )


_validate_collection_members()


def _leaf_or_primary(cid: str) -> str:
    """``cid`` when it names a configured leaf, else the primary collection."""
    cfg = TAXII_COLLECTION_MAP.get(cid)
    if cfg is not None and not cfg.members:
        return cid
    return TAXII_COLLECTION_ID


# Where the two write/ingest routes land. The manual feed (dashboard entry +
# CSV/Excel import) and the community feed (OTX + third-party TAXII pullers)
# are the leaves; the aggregate above is their union, which is what a
# consumer with broad scope polls. Each falls back to the primary collection,
# so a single-collection deployment behaves exactly as it did before.
DEFAULT_MANUAL_COLLECTION_ID = _leaf_or_primary('gt_intel')
DEFAULT_COMMUNITY_COLLECTION_ID = _leaf_or_primary('comm_intel')


def _stix_now() -> str:
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')


def _stix_ts(value: Optional[datetime]) -> Optional[str]:
    """Format a stored datetime as a STIX 2.1 timestamp, or None.

    Stored datetimes are naive UTC (`datetime.utcnow`), which is what STIX
    wants once suffixed with 'Z'. A tz-aware value is normalised to UTC first.
    """
    if value is None:
        return None
    if value.tzinfo is not None:
        value = value - value.utcoffset()
    return value.strftime('%Y-%m-%dT%H:%M:%SZ')


_HASH_KEY_BY_ALGO = {
    'md5': 'MD5', 'sha1': 'SHA-1', 'sha256': 'SHA-256', 'sha512': 'SHA-512',
}


# Stored types that carry a single IOC value (rendered as an indicator).
_IOC_STORED_TYPES = frozenset({
    'ipv4-addr', 'domain-name', 'file-hash', 'indicator',
    'url', 'email-addr', 'ipv6-addr', 'mac-addr',
    'windows-registry-key', 'autonomous-system',
})


def _ioc_value(obj: ThreatIntel) -> Optional[str]:
    """The single value an IOC object carries (or None)."""
    return (obj.ip_address or obj.domain or obj.hash_value or obj.value
            or obj.name or None)


def _ioc_pattern(obj: ThreatIntel) -> Optional[str]:
    """A STIX 2.1 pattern string for an IOC object, or None if none applies."""
    if obj.object_type == 'file-hash' and obj.hash_value:
        algo = (obj.labels[0] if obj.labels else 'sha256').lower()
        key = _HASH_KEY_BY_ALGO.get(algo, 'SHA-256')
        return f"[file:hashes.'{key}' = '{obj.hash_value}']"
    if obj.object_type == 'windows-registry-key' and obj.value:
        return f"[windows-registry-key:key = '{obj.value}']"
    if obj.object_type == 'autonomous-system' and obj.value:
        return f"[autonomous-system:number = '{obj.value}']"
    value = _ioc_value(obj)
    if not value:
        return None
    fixed = {
        'ipv4-addr': '[ipv4-addr:value = ',
        'domain-name': '[domain-name:value = ',
        'url': '[url:value = ',
        'email-addr': '[email-addr:value = ',
        'ipv6-addr': '[ipv6-addr:value = ',
        'mac-addr': '[mac-addr:value = ',
    }.get(obj.object_type)
    if fixed:
        return f"{fixed}'{value}']"
    # Free-form value: derive the pattern from the value's shape.
    guessed, algo = _guess_object_type(str(value))
    if guessed == 'ipv4-addr':
        return f"[ipv4-addr:value = '{value}']"
    if guessed == 'domain-name':
        return f"[domain-name:value = '{value}']"
    if guessed == 'file-hash':
        key = _HASH_KEY_BY_ALGO.get(algo or 'sha256', 'SHA-256')
        return f"[file:hashes.'{key}' = '{value}']"
    if guessed == 'url':
        return f"[url:value = '{value}']"
    if guessed == 'email-addr':
        return f"[email-addr:value = '{value}']"
    if guessed == 'ipv6-addr':
        return f"[ipv6-addr:value = '{value}']"
    if guessed == 'mac-addr':
        return f"[mac-addr:value = '{value}']"
    if guessed == 'autonomous-system':
        return f"[autonomous-system:number = '{value}']"
    return None


def _served_confidence(obj: ThreatIntel) -> int:
    """The confidence a consumer sees.

    Uses the pipeline's computed ``score`` when it exists, falling back to the
    source's own ``confidence`` claim otherwise (manual intel, or scoring was
    off at ingest). The two are different things — ``confidence`` is what the
    feed said, ``score`` is our cross-source judgement — and conflating them is
    exactly what let OTX's flat 70 leak into the feed.
    """
    if obj.score is not None:
        return max(0, min(100, int(obj.score)))
    return int(obj.confidence or 0)


def _ioc_stix_object(obj: ThreatIntel) -> Optional[Dict[str, Any]]:
    """A spec-valid STIX 2.1 *indicator* for an IOC object.

    Indicators are the shape a threat-intel consumer (Vision One / XDR) maps
    into detections, and the only one that may legally carry ``revoked`` /
    ``labels`` / ``confidence``. Free text no STIX pattern can express falls
    back to the legacy ``x-ti-indicator`` extension object.
    """
    now = _stix_now()
    created = _stix_ts(obj.created) or now
    modified = _stix_ts(obj.modified) or created
    pattern = _ioc_pattern(obj)
    if not pattern:
        value = _ioc_value(obj)
        if not value:
            return None
        # Unrecognizable free text: community extension type (x- prefix).
        return {
            'spec_version': '2.1',
            'type': 'x-ti-indicator',
            'id': 'x-ti-indicator--' + uuid.uuid5(uuid.NAMESPACE_OID, value).hex,
            'created': created,
            'modified': modified,
            'value': value,
            'labels': obj.labels or [],
            'confidence': _served_confidence(obj),
        }
    out: Dict[str, Any] = {
        'spec_version': '2.1',
        'type': 'indicator',
        'id': 'indicator--' + uuid.uuid5(uuid.NAMESPACE_OID, pattern).hex,
        'created': created,
        'modified': modified,
        'revoked': bool(obj.revoked),
        'labels': obj.labels or [],
        'confidence': _served_confidence(obj),
        'pattern': pattern,
        'pattern_type': 'stix',
        'pattern_version': '2.1',
        # Prefer the source's validity start (kept at ingest); else the
        # object's own created time.
        'valid_from': (obj.valid_from.strftime('%Y-%m-%dT%H:%M:%SZ')
                       if obj.valid_from else created),
    }
    if obj.name:
        out['name'] = obj.name
    if obj.description:
        out['description'] = obj.description
    return out


def _stix_uuid_id(obj_type: str, stix_id: Optional[str], seed: str) -> str:
    """Return a spec-valid STIX id: keep ``stix_id`` when it is
    ``<type>--<uuid>``, else derive a deterministic uuid5-based one.

    STIX requires an id of the form ``<object-type>--<UUID>``; objects that
    were ingested with a human/short id (manual entry, some pullers) would
    otherwise be served as invalid STIX and rejected by strict consumers.
    """
    if stix_id and stix_id.startswith(obj_type + '--'):
        try:
            uuid.UUID(stix_id.split('--', 1)[1])
            return stix_id
        except (ValueError, AttributeError):
            pass
    return f'{obj_type}--{uuid.uuid5(uuid.NAMESPACE_OID, seed)}'


def threat_intel_to_stix21(obj: ThreatIntel) -> Optional[Dict[str, Any]]:
    """Render a stored object as a standard STIX 2.1 object (JSON-able).

    IOC values render as STIX 2.1 **indicators** (a ``pattern`` + ``valid_from``)
    — the shape a threat-intel consumer (Vision One / XDR) maps into
    Suspicious Object Management, and the only shape that can legally carry
    ``revoked`` / ``labels`` / ``confidence``. (Serving raw SCOs with those
    SDO-only fields is *invalid* STIX 2.1 and gets rejected by strict
    consumers.) Non-IOC objects — malware / threat-actor / campaign /
    relationship — render as their own SDO/SRO type.
    """
    now = _stix_now()
    # Serve the *stored* timestamps: `created` is immutable per object and
    # `modified` only moves on a real change. Falling back to `now` keeps
    # objects built outside the row path (tests, ad-hoc callers) renderable.
    created = _stix_ts(obj.created) or now
    modified = _stix_ts(obj.modified) or created
    common = {
        'spec_version': '2.1',
        'created': created,
        'modified': modified,
        'revoked': bool(obj.revoked),
    }

    # IOC values -> indicator (pattern derived from the stored type/value).
    if obj.object_type in _IOC_STORED_TYPES:
        return _ioc_stix_object(obj)

    # SDOs: malware / threat-actor / campaign (UI-fed) plus identity /
    # attack-pattern / vulnerability (community TAXII feeds).
    if obj.object_type in ('malware', 'threat-actor', 'campaign',
                           'identity', 'attack-pattern', 'vulnerability'):
        base: Dict[str, Any] = {
            **common,
            'type': obj.object_type,
            'id': _stix_uuid_id(obj.object_type, obj.stix_id,
                                f'{obj.object_type}:{obj.name or obj.stix_id}'),
            'labels': obj.labels or [],
            'confidence': _served_confidence(obj),
        }
        if obj.object_type == 'malware':
            base['name'] = obj.name or 'Unnamed malware'
            base['is_family'] = True  # stored model is family-level, not binary
        elif obj.object_type == 'threat-actor':
            base['name'] = obj.name or 'Unknown threat actor'
            base['threat_actor_types'] = ['unknown']  # open-vocab, required
        elif obj.object_type == 'campaign':
            base['name'] = obj.name or 'Unnamed campaign'
        elif obj.object_type == 'identity':
            base['name'] = obj.name or 'Unknown identity'
            base['identity_class'] = 'unknown'        # REQUIRED by STIX
        elif obj.object_type == 'attack-pattern':
            base['name'] = obj.name or 'Unnamed attack pattern'  # name REQUIRED
        else:  # vulnerability
            base['name'] = obj.name or 'Unnamed vulnerability'    # name REQUIRED
        return base

    # STIX report (community feeds bundle indicators into reports).
    if obj.object_type == 'report':
        refs: List[str] = []
        if obj.object_refs:
            try:
                refs = json.loads(obj.object_refs) or []
            except (TypeError, ValueError):
                refs = []
        if not refs:
            return None              # object_refs is REQUIRED; skip if unknown
        return {
            **common,
            'type': 'report',
            'id': _stix_uuid_id('report', obj.stix_id,
                                'report:' + (obj.name or obj.stix_id)),
            'name': obj.name or 'Threat report',
            'object_refs': refs,
            'published': common['created'],
            'labels': obj.labels or [],
            'confidence': _served_confidence(obj),
        }

    # STIX relationship (the graph edge).
    if obj.object_type == 'relationship':
        if not obj.source_ref or not obj.relationship_type or not obj.target_ref:
            return None
        return {
            **common,
            'type': 'relationship',
            'id': obj.stix_id,
            'relationship_type': obj.relationship_type,
            'source_ref': obj.source_ref,
            'target_ref': obj.target_ref,
            'labels': obj.labels or [],
            'confidence': _served_confidence(obj),
        }

    # Any other stored type is not servable.
    return None


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

# Known-legitimate filter — values to keep OUT of the Vision One feed.
# A community object whose value matches one of these is WITHHELD, so Vision One
# never sees it and cannot block real traffic on it.
#   benign_values  — exact values (any type), case-insensitive
#   benign_domains — a domain and all of its subdomains
#   benign_cidrs   — IP networks (e.g. cloud / Office 365 / CDN ranges)
# The dynamic counterpart lives in the `benign_values` table (dashboard).
FILTER_BENIGN_VALUES = {
    str(v).strip().lower()
    for v in (FILTER_CFG.get('benign_values') or [])
    if str(v).strip()
}
FILTER_BENIGN_DOMAINS = {
    str(v).strip().lower().lstrip('*.').strip('.')
    for v in (FILTER_CFG.get('benign_domains') or [])
    if str(v).strip()
}


def _parse_benign_cidrs(values: Any) -> List[Any]:
    """Parse ``intel_filter.benign_cidrs`` into ``ipaddress`` networks.

    A malformed entry is logged and skipped rather than failing startup: a
    typo in the benign list must not take the whole feed down.
    """
    nets: List[Any] = []
    for raw in (values or []):
        s = str(raw or '').strip()
        if not s:
            continue
        try:
            nets.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            logger.warning("intel_filter.benign_cidrs: ignoring invalid network %r", s)
    return nets


FILTER_BENIGN_CIDRS = _parse_benign_cidrs(FILTER_CFG.get('benign_cidrs'))


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


# ---------------------------------------------------------------------------
# Known-legitimate filter (keep legitimate values OUT of the feed)
# ---------------------------------------------------------------------------
# The gate rules are value-agnostic: they catch a *kind* of noise but cannot
# know that a specific domain is legitimate. So a community feed that flags,
# say, login.microsoftonline.com would be served — and Vision One would block
# real traffic. A value named here is instead WITHHELD from the feed. Two
# sources:
#   * config.yaml `intel_filter.benign_values / benign_domains / benign_cidrs`
#   * the `benign_values` table (dashboard; no restart needed)
# The table is mirrored into in-memory sets so a poll never touches the DB;
# load_benign_values() rebuilds them at startup and on every change.

_BENIGN_KINDS = ('exact', 'domain', 'cidr')

_benign_lock = threading.Lock()
_BENIGN_EXACT: "set[str]" = set()
_BENIGN_DOMAINS: "set[str]" = set()
_BENIGN_CIDRS: List[Any] = []


def _normalise_benign(value: Any,
                      kind: str) -> Tuple[Optional[str], Optional[str]]:
    """Validate + normalise a benign ``(value, kind)``.

    Returns ``(normalised_value, None)`` or ``(None, error)``. The value is
    stored in the form the matcher compares against: lowercased for exact and
    domain, the canonical ``network/prefix`` string for CIDR.
    """
    s = str(value or '').strip()
    if not s:
        return None, 'value is required'
    kind = str(kind or 'exact').lower()
    if kind == 'exact':
        return s.lower(), None
    if kind == 'domain':
        d = s.lower().lstrip('*.').strip('.')
        if not d or not _DOMAIN_RE.match(d):
            return None, f'not a valid domain: {value!r}'
        return d, None
    if kind == 'cidr':
        try:
            return str(ipaddress.ip_network(s, strict=False)), None
        except ValueError:
            return None, f'not a valid CIDR network: {value!r}'
    return None, 'kind must be one of exact|domain|cidr'


def load_benign_values() -> int:
    """Rebuild the in-memory benign caches from the ``benign_values`` table.

    Called at startup and after every create/delete, so the read path (a TAXII
    poll) never queries the database. Returns the number of rows loaded.
    """
    session = create_session()
    try:
        rows = [(r.value, str(r.kind or 'exact'))
                for r in session.query(BenignValue).all()]
    finally:
        session.close()
    exact: "set[str]" = set()
    domains: "set[str]" = set()
    cidrs: List[Any] = []
    for value, kind in rows:
        v = str(value or '').strip()
        if not v:
            continue
        if kind == 'domain':
            domains.add(v.lower())
        elif kind == 'cidr':
            try:
                cidrs.append(ipaddress.ip_network(v, strict=False))
            except ValueError:
                continue
        else:
            exact.add(v.lower())
    with _benign_lock:
        _BENIGN_EXACT.clear()
        _BENIGN_EXACT.update(exact)
        _BENIGN_DOMAINS.clear()
        _BENIGN_DOMAINS.update(domains)
        _BENIGN_CIDRS.clear()
        _BENIGN_CIDRS.extend(cidrs)
    return len(rows)


def _is_benign_value(value: Any) -> bool:
    """True when ``value`` is on the known-legitimate list (withhold it).

    Checks the config benign lists and the dashboard entries: an exact match, a
    domain match (the value itself or a subdomain of it), or a CIDR match when
    the value is IP-shaped.
    """
    s = str(value or '').strip()
    if not s:
        return False
    low = s.lower()
    if low in FILTER_BENIGN_VALUES:
        return True
    with _benign_lock:
        if low in _BENIGN_EXACT:
            return True
        domains = tuple(_BENIGN_DOMAINS)
        cidrs = list(_BENIGN_CIDRS)
    for d in tuple(FILTER_BENIGN_DOMAINS) + domains:
        if low == d or low.endswith('.' + d):
            return True
    nets = list(FILTER_BENIGN_CIDRS) + cidrs
    if nets:
        try:
            ip = ipaddress.ip_address(s)
        except ValueError:
            return False
        if any(ip in net for net in nets):
            return True
    return False


def _object_benign(obj: ThreatIntel) -> bool:
    """True when any value of ``obj`` is known-legitimate (withhold it).

    Manual intel never reaches the gate, so this is only consulted for
    community-sourced objects.
    """
    values: List[Any] = [obj.ip_address, obj.domain, obj.hash_value,
                         obj.name, obj.value]
    # A URL is only ever a whole URL; match its host too, so a benign_domains
    # entry covers a URL object pointing at that domain.
    if obj.object_type == 'url' and obj.value:
        try:
            host = urllib.parse.urlsplit(str(obj.value)).hostname
            if host:
                values.append(host)
        except ValueError:
            pass
    return any(v and _is_benign_value(v) for v in values)
# Scoring pipeline — Phase 1 (offline)
# ---------------------------------------------------------------------------
# Sits between a community poller and ingest, deciding which collection an
# indicator lands in: a high score goes to the served community collection, the
# rest to a quarantine collection the consumer never sees.
#
# Phase 1 uses ONLY local signals — no network egress, no API keys — so it adds
# no new failure modes and is fully testable offline. Layer 3 (VirusTotal /
# AbuseIPDB / RDAP) is designed to feed the same score later via the `extra`
# argument of score_from_summary(); nothing here needs to change for that.
#
# Every weight is configurable and the per-signal breakdown is persisted with
# the object, so "why was this quarantined?" is always answerable afterwards.

SCORING_CFG = CONFIG.get('scoring', {}) or {}
SCORING_ENABLED = bool(SCORING_CFG.get('enabled', False))
SCORING_THRESHOLD = int(SCORING_CFG.get('threshold', 75))
SCORING_QUARANTINE_COLLECTION = str(
    SCORING_CFG.get('quarantine_collection') or 'quarantine')
SCORING_LARGE_PULSE_MIN = int(SCORING_CFG.get('large_pulse_min', 10))

# Weights for each local signal. Deliberately transparent and tunable: the
# dry-run harness (python server.py --score-sample) exists to tune these
# against real data rather than guess.
DEFAULT_SCORE_WEIGHTS: Dict[str, int] = {
    'base': 30,                 # floor, so nothing scores a spurious zero
    'pulse_recent_7d': 15,      # pulse modified within a week
    'pulse_recent_30d': 8,      # ...within a month
    'pulse_has_adversary': 10,  # pulse names a threat actor
    'pulse_has_tags': 5,
    'pulse_large': 5,           # >= scoring.large_pulse_min indicators
    'corroborated_2': 10,       # same value from >= 2 distinct sources
    'corroborated_3': 20,       # ... >= 3
    'corroborated_4': 30,       # ... >= 4 (the strongest signal available)
    # Per-source signals, from the ioc_observations table (Phase 2a).
    'otx_multi_pulse': 10,      # same value in >= 2 distinct OTX pulses
    'threatfox_conf_high': 20,  # ThreatFox confidence_level >= 75
    'threatfox_conf_mid': 10,   # ... >= 50
    'feodo_c2': 30,             # present in Feodo's curated botnet-C2 list
    'urlhaus': 15,              # present in URLhaus
}
SCORE_WEIGHTS: Dict[str, int] = {
    **DEFAULT_SCORE_WEIGHTS,
    **{k: int(v) for k, v in (SCORING_CFG.get('weights') or {}).items()
       if k in DEFAULT_SCORE_WEIGHTS},
}

# The source's own `confidence` is deliberately NOT an input. Every automated
# path writes a constant for it (70 for OTX, 50 elsewhere), so it carries no
# per-indicator signal — including it would shift every score by the same
# amount and discriminate nothing.


if SCORING_ENABLED:
    # Two misconfigurations here are silent and costly, so they are checked at
    # import rather than discovered later from a feed that looks wrong.
    if SCORING_QUARANTINE_COLLECTION not in TAXII_COLLECTION_MAP:
        logger.error(
            "scoring.enabled is true but %r is not a configured collection — "
            "quarantined objects would be filed under an id nothing can list. "
            "Add it to taxii.collections.",
            SCORING_QUARANTINE_COLLECTION,
        )
    elif any(SCORING_QUARANTINE_COLLECTION in c.members
             for c in TAXII_COLLECTIONS):
        logger.error(
            "Quarantine collection %r is a member of an aggregate, so "
            "quarantined intel WOULD be served to consumers. Remove it from "
            "that collection's `members`.",
            SCORING_QUARANTINE_COLLECTION,
        )


def _pulse_age_days(pulse: Dict[str, Any]) -> Optional[float]:
    """Age of an OTX pulse in days (from ``modified``, else ``created``)."""
    for key in ('modified', 'created'):
        stamp = _parse_iso_naive(pulse.get(key)) if pulse.get(key) else None
        if stamp is not None:
            return (datetime.utcnow() - stamp).total_seconds() / 86400.0
    return None




def pulse_filter_reason(pulse: Optional[Dict[str, Any]]) -> Optional[str]:
    """Layer 2: why this pulse fails the metadata/age filter, or None."""
    if not pulse:
        return None
    max_age = SCORING_CFG.get('max_pulse_age_days')
    if max_age:
        age = _pulse_age_days(pulse)
        if age is not None and age > float(max_age):
            return f'pulse is {age:.0f}d old (limit {int(max_age)}d)'
    if SCORING_CFG.get('require_adversary') and not str(
            pulse.get('adversary') or '').strip():
        return 'pulse names no adversary'
    return None




# --- observations (Phase 2a: cross-source corroboration) -------------------
# The score needs to know WHICH sources observed a value, but the merged
# stix_objects row keeps only one. These helpers persist every sighting and
# turn them into the per-signal summary the score is computed from.

def _normalise_obs_value(value: Any) -> str:
    return str(value or '').strip().lower()


def _pulse_detail(pulse: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The OTX pulse fields worth persisting for scoring/audit."""
    if not pulse:
        return {}
    return {
        'pulse': str(pulse.get('id') or pulse.get('name') or ''),
        'adversary': str(pulse.get('adversary') or ''),
        'tags': list(pulse.get('tags') or []),
        'indicator_count': int(pulse.get('indicator_count') or 0),
        'modified': str(pulse.get('modified') or ''),
    }


def build_observation(descriptor: Dict[str, Any],
                      context: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """One observation record for an ingest candidate, or None."""
    context = context or {}
    value, obj_type = _indicator_value(descriptor)
    value = _normalise_obs_value(value)
    source = str(context.get('source') or 'unknown')
    if not value or not source:
        return None
    obs_key = str(context.get('obs_key') or source)
    raw = context.get('raw_confidence')
    try:
        raw_conf = int(raw) if raw is not None else None
    except (TypeError, ValueError):
        raw_conf = None
    detail = context.get('detail')
    if not isinstance(detail, dict):
        detail = _pulse_detail(context.get('pulse'))
    return {
        'value': value,
        'object_type': obj_type,
        'source': source,
        'observation_key': obs_key,
        'raw_confidence': raw_conf,
        'detail': detail,
    }


def record_observations(observations: List[Dict[str, Any]]) -> int:
    """Upsert observations, deduped on (value, source, observation_key).

    Refreshing an existing observation updates ``last_seen`` rather than
    inserting a duplicate, so cross-source counts stay meaningful when a feed
    is polled repeatedly.
    """
    if not observations:
        return 0
    session = create_session()
    inserted = 0
    try:
        values = sorted({o['value'] for o in observations})
        existing: Dict[Tuple[str, str, str], Any] = {}
        for start in range(0, len(values), 500):
            chunk = values[start:start + 500]
            for row in session.query(IocObservation).filter(
                    IocObservation.value.in_(chunk)):
                existing[(row.value, row.source, row.observation_key)] = row
        now = datetime.utcnow()
        for obs in observations:
            key = (obs['value'], obs['source'], obs['observation_key'])
            row = existing.get(key)
            if row is not None:
                row.last_seen = now
                if obs.get('raw_confidence') is not None:
                    row.raw_confidence = obs['raw_confidence']
                continue
            row = IocObservation(
                id=uuid.uuid4().hex,
                value=obs['value'],
                object_type=obs['object_type'],
                source=obs['source'],
                observation_key=obs['observation_key'],
                observed_at=now,
                last_seen=now,
                raw_confidence=obs.get('raw_confidence'),
                detail=json.dumps(obs.get('detail') or {}, sort_keys=True),
            )
            session.add(row)
            existing[key] = row
            inserted += 1
        session.commit()
    except Exception as exc:
        session.rollback()
        logger.error("Could not record IOC observations: %s", exc)
        return 0
    finally:
        session.close()
    return inserted


def _new_obs_summary() -> Dict[str, Any]:
    return {'sources': set(), 'otx_pulses': set(), 'otx_adversary': False,
            'otx_tags': False, 'otx_latest': None, 'otx_indicator_count': 0,
            'threatfox_conf': 0, 'feodo': False, 'urlhaus': False,
            'latest': None}


def _merge_observation(summary: Dict[str, Dict[str, Any]],
                       obs: Dict[str, Any]) -> None:
    """Fold one observation into ``summary[value]``."""
    value = obs['value']
    entry = summary.setdefault(value, _new_obs_summary())
    source = str(obs.get('source') or '')
    entry['sources'].add(source)
    detail = obs.get('detail')
    if isinstance(detail, str):
        try:
            detail = json.loads(detail)
        except (TypeError, ValueError):
            detail = {}
    detail = detail if isinstance(detail, dict) else {}
    if source == 'otx':
        if detail.get('pulse'):
            entry['otx_pulses'].add(str(detail['pulse']))
        if detail.get('adversary'):
            entry['otx_adversary'] = True
        if detail.get('tags'):
            entry['otx_tags'] = True
        try:
            entry['otx_indicator_count'] = max(
                int(entry.get('otx_indicator_count') or 0),
                int(detail.get('indicator_count') or 0))
        except (TypeError, ValueError):
            pass
        stamp = _parse_iso_naive(detail.get('modified')) if detail.get('modified') else None
        if stamp and (entry['otx_latest'] is None or stamp > entry['otx_latest']):
            entry['otx_latest'] = stamp
    elif source == 'threatfox':
        try:
            if obs.get('raw_confidence') is not None:
                entry['threatfox_conf'] = max(entry['threatfox_conf'],
                                              int(obs['raw_confidence']))
        except (TypeError, ValueError):
            pass
    elif source == 'feodo':
        entry['feodo'] = True
    elif source == 'urlhaus':
        entry['urlhaus'] = True
    seen = obs.get('last_seen') or obs.get('observed_at')
    if isinstance(seen, datetime) and (entry['latest'] is None or seen > entry['latest']):
        entry['latest'] = seen


def observation_summaries(values: List[str]) -> Dict[str, Dict[str, Any]]:
    """Load stored observations for ``values`` into per-value summaries."""
    wanted = sorted({_normalise_obs_value(v) for v in values if v})
    if not wanted:
        return {}
    summary: Dict[str, Dict[str, Any]] = {}
    session = create_session()
    try:
        for start in range(0, len(wanted), 500):
            chunk = wanted[start:start + 500]
            rows = session.query(IocObservation).filter(
                IocObservation.value.in_(chunk)).all()
            for row in rows:
                _merge_observation(summary, {
                    'value': row.value, 'source': row.source,
                    'raw_confidence': row.raw_confidence,
                    'detail': row.detail, 'last_seen': row.last_seen,
                })
    except Exception as exc:            # never break a poll on a scoring read
        logger.error("Observation lookup failed: %s", exc)
    finally:
        session.close()
    return summary


def score_from_summary(entry: Optional[Dict[str, Any]],
                       extra: Optional[Dict[str, int]] = None
                       ) -> Tuple[int, Dict[str, int]]:
    """Compute the 0-100 score from a value's observation summary.

    Every component is named in the breakdown, so a served or quarantined
    decision can be explained signal-by-signal after the fact.

    ``extra`` is the enrichment seam: a later stage passes e.g.
    ``{'vt_detections': 20, 'rdap_new_domain': 10}`` and it sums in exactly
    like a local signal, with the same auditable breakdown.
    """
    weights = SCORE_WEIGHTS
    parts: Dict[str, int] = {}

    def add(key: str, points: int) -> None:
        if points:
            parts[key] = int(points)

    add('base', weights['base'])
    entry = entry or _new_obs_summary()
    sources = entry.get('sources') or set()
    if len(sources) >= 4:
        add('corroborated_4', weights['corroborated_4'])
    elif len(sources) == 3:
        add('corroborated_3', weights['corroborated_3'])
    elif len(sources) == 2:
        add('corroborated_2', weights['corroborated_2'])

    if entry.get('otx_pulses'):
        if len(entry['otx_pulses']) >= 2:
            add('otx_multi_pulse', weights['otx_multi_pulse'])
        latest = entry.get('otx_latest')
        if latest is not None:
            age = (datetime.utcnow() - latest).total_seconds() / 86400.0
            if age <= 7:
                add('pulse_recent_7d', weights['pulse_recent_7d'])
            elif age <= 30:
                add('pulse_recent_30d', weights['pulse_recent_30d'])
        if entry.get('otx_adversary'):
            add('pulse_has_adversary', weights['pulse_has_adversary'])
        if entry.get('otx_tags'):
            add('pulse_has_tags', weights['pulse_has_tags'])
        if int(entry.get('otx_indicator_count') or 0) >= SCORING_LARGE_PULSE_MIN:
            add('pulse_large', weights['pulse_large'])

    conf = int(entry.get('threatfox_conf') or 0)
    if conf >= 75:
        add('threatfox_conf_high', weights['threatfox_conf_high'])
    elif conf >= 50:
        add('threatfox_conf_mid', weights['threatfox_conf_mid'])
    if entry.get('feodo'):
        add('feodo_c2', weights['feodo_c2'])
    if entry.get('urlhaus'):
        add('urlhaus', weights['urlhaus'])
    for key, points in (extra or {}).items():
        add(key, int(points))

    return max(0, min(100, sum(parts.values()))), parts


def _indicator_value(descriptor: Dict[str, Any]) -> Tuple[str, str]:
    """``(value, object_type)`` for an ingest descriptor, best effort.

    Reads the same shapes the ingest path accepts (flat, or type-nested).
    """
    obj_type = str(descriptor.get('type') or '')
    body = descriptor.get('object') or {}
    nested = body.get(obj_type) if isinstance(body, dict) else None
    inner = nested if isinstance(nested, dict) else body
    if not isinstance(inner, dict):
        inner = {}
    if obj_type == 'file-hash':
        hashes = inner.get('hash_value')
        if isinstance(hashes, dict):
            return str(hashes.get('value') or ''), obj_type
        return str(hashes or descriptor.get('hash_value') or ''), obj_type
    return str(inner.get('value') or inner.get('key') or inner.get('number')
               or descriptor.get('value') or ''), obj_type



def route_by_score(candidates: List[Tuple[Dict[str, Any], Optional[Dict[str, Any]]]]
                   ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]],
                              Dict[str, Any],
                              Dict[str, Tuple[int, Dict[str, int]]],
                              List[Dict[str, Any]]]:
    """Score a poll's candidates from their stored + in-batch observations.

    ``candidates`` is ``[(ingest_descriptor, context), ...]``. ``context`` is a
    dict describing the sighting::

        {'source': 'otx'|'threatfox'|'feodo'|'urlhaus'|...,
         'obs_key': '<dedupe key within that source>',
         'pulse': <OTX pulse or None>,
         'raw_confidence': <source's own 0-100 or None>,
         'detail': <optional dict overriding the derived detail>}

    The score is computed from :class:`IocObservation` summaries (existing
    rows merged with this batch), so corroboration counts **distinct sources**
    rather than the single merged ``stix_objects`` row. Returns
    ``(accepted, quarantined, report, scores, observations)``; the caller
    persists ``scores`` with the ingest and ``observations`` afterwards.

    Benignness is deliberately NOT decided here: the known-legitimate filter
    (``_is_benign_value`` / ``_object_benign``) already withholds those values
    at read time, with a dashboard-editable list. Duplicating that decision at
    ingest would create a second source of truth.
    """
    report: Dict[str, Any] = {
        'enabled': SCORING_ENABLED,
        'threshold': SCORING_THRESHOLD,
        'candidates': len(candidates),
        'accepted': 0,
        'quarantined': 0,
    }
    observations = [o for o in (build_observation(d, c) for d, c in candidates)
                    if o]
    if not SCORING_ENABLED:
        # Feature off: unchanged behaviour, everything is accepted. The
        # observations are still returned so history accumulates for the day
        # scoring is switched on.
        return [c[0] for c in candidates], [], report, {}, observations

    summaries = observation_summaries([o['value'] for o in observations])
    # Fold this batch in so sightings inside one poll corroborate immediately.
    now = datetime.utcnow()
    for obs in observations:
        _merge_observation(summaries, {**obs, 'last_seen': now})

    accepted: List[Dict[str, Any]] = []
    quarantined: List[Dict[str, Any]] = []
    scores: Dict[str, Tuple[int, Dict[str, int]]] = {}
    for descriptor, _context in candidates:
        value = _normalise_obs_value(_indicator_value(descriptor)[0])
        score, breakdown = score_from_summary(summaries.get(value))
        stix_id = str(descriptor.get('id') or '')
        if stix_id:
            scores[stix_id] = (score, breakdown)
        if score >= SCORING_THRESHOLD:
            accepted.append(descriptor)
        else:
            quarantined.append(descriptor)

    report['accepted'] = len(accepted)
    report['quarantined'] = len(quarantined)
    return accepted, quarantined, report, scores, observations


def community_intel_reason(obj: ThreatIntel, row: 'STIXObject') -> Optional[str]:
    """Return the reason a *community-sourced* object is withheld, or None
    to serve it.

    Called only for objects whose ``source`` is in
    ``FILTER_COMMUNITY_SOURCES`` (see ``build_stix_bundle``). Manual intel
    is never passed here.
    """
    # 0) Known-legitimate filter: a community object whose value is on the
    #    benign list is WITHHELD, so Vision One never sees it (and therefore
    #    cannot block legitimate traffic on it). See _object_benign.
    if _object_benign(obj):
        return 'benign'

    # 1) Explicit blocklist (exact value match).
    for value in (obj.ip_address, obj.domain, obj.hash_value, obj.name, obj.value):
        if value and value.lower() in FILTER_BLOCKLIST:
            return 'blocklist'

    # 2) Private / reserved IPs (honors the drop_private_ips toggle).
    if FILTER_DROP_PRIVATE_IPS:
        for ipv in (
            obj.ip_address,
            obj.value if obj.object_type == 'ipv6-addr' else None,
        ):
            if ipv and _is_private_or_reserved_ip(ipv):
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
    'benign': 'Known legitimate (kept out of the feed)',
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


def _encode_cursor(modified_iso: str, stix_id: str) -> str:
    """Opaque keyset cursor: base64url({"m": modified ISO, "i": stix_id})."""
    raw = json.dumps({'m': modified_iso, 'i': stix_id}, separators=(',', ':'))
    return base64.urlsafe_b64encode(raw.encode('utf-8')).decode('ascii').rstrip('=')


def _decode_cursor(cursor: str) -> Optional[Tuple[str, str]]:
    """Decode a cursor back to (modified_iso, stix_id), or None if malformed."""
    try:
        padded = cursor + '=' * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded).decode('utf-8'))
        m, i = str(data['m']), str(data['i'])
        if not m or not i:
            return None
        return m, i
    except Exception:
        return None


def build_stix_bundle(since: Optional[str] = None,
                      match_types: Optional[List[str]] = None,
                      match_ids: Optional[List[str]] = None,
                      added_after: Optional[str] = None,
                      collection: Optional[str] = None,
                      limit: Optional[int] = None,
                      next_cursor: Optional[str] = None,
                      allowed_types: Optional[List[str]] = None) -> Tuple[Dict[str, Any], bool, Optional[str]]:
    """Build a STIX 2.1 bundle of the current feed (optionally filtered/paged).

    TAXII 2.1 Get Objects parameters:
      * ``since`` / ``added_after``: only objects modified after this
        ISO-8601 timestamp (``added_after`` is the spec name; ``since`` is
        accepted for back-compat). A malformed timestamp raises ValueError
        (the endpoint turns it into a 400).
      * ``match_types``: ``match[type]`` - only these STIX object types.
      * ``match_ids``: ``match[id]`` - only these exact object ids.
      * ``collection``: only objects of this TAXII collection (None = all).
      * ``allowed_types``: a per-API-key ALLOW-LIST of stored object types
        (None = unrestricted). Applied in ADDITION to ``match_types`` — a
        client can narrow further but never widen past its key's scope.
      * ``limit`` / ``next_cursor``: keyset pagination in (modified, stix_id)
        order — pages stay consistent while the feed changes underneath and
        never loop. Returns ``more`` (more pages exist) and ``next_cursor``
        (opaque; pass it back as ?next=).

    Revoked objects are INCLUDED but rendered with ``revoked: true`` (clients
    purge them); they are never silently dropped.
    Returns ``(bundle, more, next_cursor)``.
    """
    session = create_session()
    try:
        q = session.query(STIXObject)
        cutoff = since or added_after
        if cutoff:
            cutoff_dt = _parse_iso_ts(cutoff)
            if cutoff_dt is None:
                raise ValueError(f'bad since/added_after timestamp: {cutoff!r}')
            q = q.filter(STIXObject.modified >= cutoff_dt)
        if collection:
            # An aggregate reads as the union of its members; a leaf is a
            # plain equality filter.
            q = _apply_collection_filter(q, collection)
        # match[id] is applied after rendering (a client may reference either
        # the served indicator id or our stored id), so it is not a SQL filter.
        match_id_set = {str(i) for i in match_ids} if match_ids else None
        # Apply match[type] at the SQL level too so page limits stay correct
        # even when most rows don't match the requested types.
        type_filter = ({str(t) for t in match_types} if match_types else None)
        if type_filter and 'indicator' in type_filter:
            # Every IOC value is *served* as an `indicator`, so a client
            # asking for match[type]=indicator must match all of them — not
            # only rows whose stored type happens to be 'indicator'.
            type_filter = type_filter | _IOC_STORED_TYPES
        if type_filter:
            q = q.filter(STIXObject.object_type.in_(type_filter))
        # Per-key object-type allow-list (independent of, and ANDed with,
        # match[type]): the key can only ever be served the stored types it was
        # scoped to. 'indicator' expands the same way as above (it is an alias
        # for every IOC value, since those are all served as indicators).
        allowed_filter = None
        if allowed_types is not None:
            allowed_filter = {str(t) for t in allowed_types}
            if 'indicator' in allowed_filter:
                allowed_filter = allowed_filter | _IOC_STORED_TYPES
            # An empty allow-list (never produced by key validation, but
            # defensive) matches nothing rather than falling open.
            q = q.filter(STIXObject.object_type.in_(allowed_filter))

        # Keyset pagination: consistent (modified, stix_id) ordering.
        q = q.order_by(STIXObject.modified.asc(), STIXObject.stix_id.asc())
        if next_cursor:
            parsed = _decode_cursor(next_cursor)
            if parsed is None:
                raise ValueError('bad next cursor')
            m_iso, after_id = parsed
            m_dt = _parse_iso_ts(m_iso)
            if m_dt is None:
                raise ValueError('bad next cursor')
            q = q.filter(or_(
                STIXObject.modified > m_dt,
                and_(STIXObject.modified == m_dt,
                     STIXObject.stix_id > after_id),
            ))
        # A client that sends no `limit` must still not be able to make the
        # server materialise an entire collection in one response. Cap the
        # page at taxii.max_objects (the same ceiling already applied to an
        # explicit `limit`); the client pages on via `more`/`next`. Set
        # taxii.max_objects to 0 to restore unbounded pages.
        page_cap = _default_page_cap()
        page = limit if limit is not None else page_cap
        if page is not None and match_id_set is None:
            rows = q.limit(page + 1).all()
            more = len(rows) > page
            rows = rows[:page]
        else:
            # A targeted match[id] lookup is bounded by the id set itself.
            rows = q.all()
            more = False
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    objects: List[Dict[str, Any]] = []
    withheld = 0
    # Render straight from the row: the DB is the source of truth for what is
    # served, so a missing/stale memory entry can no longer silently drop an
    # object that the SQL query (and therefore the page limit) counted.
    for row in rows:
        obj = _row_to_threat_intel(row)
        # match[type] - filter on the stored type we would render
        # (matches the SQL-level filter above; kept for direct callers).
        if type_filter is not None and row.object_type not in type_filter:
            continue
        # Per-key allow-list (kept for direct callers; matches the SQL filter).
        if allowed_filter is not None and row.object_type not in allowed_filter:
            continue
        # Community-intel gate (manual intel is never gated).
        verdict = gate_verdict(obj, row)
        if verdict['gated']:
            withheld += 1
            continue
        stix = threat_intel_to_stix21(obj)
        if stix is None:
            continue
        # match[id]: accept the id the client RECEIVED (the served
        # indicator id) or our stored id.
        if match_id_set is not None and (
                row.stix_id not in match_id_set
                and stix.get('id') not in match_id_set):
            continue
        objects.append(stix)

    if withheld:
        logger.info(
            "Intel gate withheld %s community object(s) from the TAXII feed",
            withheld,
        )

    # Next-page cursor: key of the last row in the slice (SQL-level key, so
    # following ?next= continues the same keyset even if the gate/type filter
    # drops pages' worth of objects).
    nxt = None
    if more and rows:
        last = rows[-1]
        nxt = _encode_cursor(last.modified.isoformat(), last.stix_id)

    return {
        'type': 'bundle',
        'id': 'bundle--' + uuid.uuid4().hex,
        'spec_version': '2.1',
        'objects': objects,
    }, more, nxt


def _taxii_message(collection: Optional[str] = None,
                   content: Optional[Dict[str, Any]] = None,
                   more: bool = False,
                   next_cursor: Optional[str] = None) -> Dict[str, Any]:
    msg: Dict[str, Any] = {'object': 'message', 'meta': {'timestamp': _stix_now()}}
    if collection:
        msg['meta']['collection'] = collection
    # TAXII 2.1 §5.3: more is REQUIRED on Get Objects responses; next is
    # REQUIRED when more is true (the opaque cursor for the next page).
    msg['more'] = bool(more)
    if more and next_cursor:
        msg['next'] = next_cursor
    if content is not None:
        msg['content'] = {
            'object': 'content',
            'id': uuid.uuid4().hex,
            'content_type': 'application/stix+json',
            'content': content,
        }
    return msg


def _taxii_error(status: int, title: str, detail: str,
                 code: Optional[str] = None) -> Response:
    """TAXII 2.1 error response (spec §3.2): status_code as a string."""
    payload: Dict[str, Any] = {
        'status_code': str(status),
        'title': title,
        'detail': detail,
    }
    if code:
        payload['errors'] = {'code': code}
    return Response(
        json.dumps(payload),
        status=status,
        mimetype='application/taxii+json;version=2.1',
        headers={'TAXII-ServiceVersion': '2.1'},
    )


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
    """Accept HTTP Basic auth (TAXII standard) or the X-Taxii-* headers.

    Any valid principal (any collection's credentials, or the legacy/test
    override) passes — collection-level scoping happens in
    :func:`_taxii_collection_auth`.
    """
    user, pw = _request_taxii_credentials()
    return _validate_taxii_auth(user, pw)


def _taxii_collection_auth(collection_id: str) -> bool:
    """True if the request's credentials may read ``collection_id``."""
    user, pw = _request_taxii_credentials()
    return any(
        c.id == collection_id for c in _collections_readable_by(user, pw)
    )


def _taxii_base_url() -> str:
    return request.url_root.rstrip('/') + '/taxii2/'


def _collection_url(base_url: str, collection_id: str) -> str:
    return f'{base_url}collections/{collection_id}/'


def _collection_resource(base_url: str, cfg: CollectionConfig) -> Dict[str, Any]:
    """A single Collection Resource (flat — fields at top level per spec 5.2.1).

    An aggregate advertises the collections it unions in the free-form
    ``meta`` object (``meta['members']``) rather than as a non-spec
    top-level field. ``can_write`` stays false for every collection here:
    the feed is read-only to TAXII clients.
    """
    meta: Dict[str, Any] = {'collection_url': _collection_url(base_url, cfg.id)}
    if cfg.members:
        meta['members'] = list(cfg.members)
    return {
        'id': cfg.id,
        'title': cfg.title,
        'description': (
            cfg.description
            or 'Custom threat intelligence objects: IPv4/IPv6 addresses, '
               'domain names, file hashes, URLs, and indicators.'
        ),
        'can_read': True,
        'can_write': False,
        'version': '2.1',
        'created': _stix_now(),
        'meta': meta,
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
    """TAXII 2.1 Get Collections (section 5.1).

    RBAC: lists only the collections the authenticated principal's
    credentials may read (each collection has its own credentials).
    """
    if not _taxii_check_auth():
        return _taxii_unauthorized()
    user, pw = _request_taxii_credentials()
    readable = _collections_readable_by(user, pw)
    base = _taxii_base_url()
    collections = [_collection_resource(base, c) for c in readable]
    return _taxii_response({
        'object': 'collections',
        'meta': {'count': len(collections), 'first': 0, 'last': len(collections) - 1},
        'collections': collections,
    })


@app.route('/taxii2/collections/<collection_id>', methods=['GET'])
@app.route('/taxii2/collections/<collection_id>/', methods=['GET'])
def taxii_collection_info(collection_id: str):
    """TAXII 2.1 Get a Collection (section 5.2)."""
    if not _taxii_check_auth():
        return _taxii_unauthorized()
    cfg = TAXII_COLLECTION_MAP.get(collection_id)
    if cfg is None:
        return _taxii_error(404, 'Not Found',
                            f'Collection {collection_id} not found.')
    if not _taxii_collection_auth(collection_id):
        return _taxii_unauthorized()
    base = _taxii_base_url()
    info = _collection_resource(base, cfg)
    info['url'] = _collection_url(base, collection_id)
    return _taxii_response(info)


@app.route('/taxii2/collections/<collection_id>/objects', methods=['GET', 'POST'])
@app.route('/taxii2/collections/<collection_id>/objects/', methods=['GET', 'POST'])
def taxii_objects(collection_id: str):
    """TAXII 2.1 Get Objects (5.3) / Add Objects (5.4) for a collection."""
    # Authorize BEFORE resolving the collection: an unauthenticated caller must
    # not be able to tell a real collection id (401) from an unknown one (404).
    if not _taxii_check_auth():
        return _taxii_unauthorized()
    cfg = TAXII_COLLECTION_MAP.get(collection_id)
    if cfg is None:
        return _taxii_error(404, 'Not Found',
                            f'Collection {collection_id} not found.')
    if not _taxii_collection_auth(collection_id):
        return _taxii_unauthorized()

    if request.method == 'POST':
        # Add Objects: this is a read-only feed; acknowledge as a no-op.
        return _taxii_response(_last_status())

    # TAXII 2.1 Get Objects query parameters (section 5.3):
    #   since / added_after  -> only objects modified after the timestamp
    #   match[type]          -> only these STIX object types
    #   match[id]            -> only these exact object ids
    #   limit                -> max objects in this page (positive integer)
    #   next                 -> opaque cursor for the next page
    # (?since= kept as an accepted alias of added_after.)
    #
    # match[type] / match[id] accept comma-separated value lists (and a
    # parameter may be repeated); all values are a disjunction, per spec.
    def _match_values(name: str) -> List[str]:
        vals: List[str] = []
        for raw in request.args.getlist(name):
            vals.extend(p.strip() for p in str(raw).split(',') if p.strip())
        return vals

    since = request.args.get('since') or request.args.get('added_after')
    match_types = _match_values('match[type]')
    match_ids = _match_values('match[id]')
    limit = None
    raw_limit = request.args.get('limit')
    if raw_limit is not None and raw_limit != '':
        try:
            limit = int(raw_limit)
            if limit <= 0:
                raise ValueError
        except (TypeError, ValueError):
            return _taxii_error(400, 'Bad Request',
                                f'limit must be a positive integer, got {raw_limit!r}',
                                'malformed')
    next_cursor = request.args.get('next')

    # Page ceiling: the smallest of what the client asked for, what THIS API key
    # is allowed, and the server-wide taxii.max_objects. The per-key ceiling
    # lets a consumer with a per-poll ingest limit be fed incrementally instead
    # of being handed the whole collection at once. Returning fewer objects than
    # a client asked for is spec-legal (`limit` is a maximum; `more` signals it).
    key = _api_key_for(_request_taxii_credentials()[1])
    key_cap = int((key or {}).get('max_objects') or 0)
    global_cap = int(TAXII_CFG.get('max_objects') or 0)
    caps = [c for c in (limit, key_cap, global_cap) if c and c > 0]
    effective_limit = min(caps) if caps else None
    # True when the key's own ceiling is what bounds this page — the case a
    # client with a per-poll limit cares about, and the case worth logging.
    key_bound = bool(key_cap and effective_limit == key_cap
                     and (not limit or limit > key_cap))

    try:
        bundle, more, nxt = build_stix_bundle(
            since=since, match_types=match_types, match_ids=match_ids,
            collection=collection_id, limit=effective_limit,
            next_cursor=next_cursor,
            # The key's object-type allow-list bounds what this consumer can
            # ever be served; non-key auth (static creds / UI session) is None.
            allowed_types=(key or {}).get('types'),
        )
    except ValueError as exc:
        return _taxii_error(400, 'Bad Request', str(exc), 'malformed')

    if key_bound and more:
        # This is the log line that answers "does my consumer paginate?".
        # A client that follows the cursor shows up as `next cursor`; one that
        # ignores it (and polls without added_after) would sit on the same
        # first page forever, and shows up as `no cursor, no added_after`.
        logger.info(
            "API key %s served a capped page (max_objects=%d, %d object(s), "
            "more remain); request used %s",
            (key or {}).get('prefix') or '?', key_cap,
            len(bundle.get('objects') or []),
            'the next cursor' if next_cursor else
            ('added_after' if since else 'no cursor and no added_after'),
        )

    if TAXII_OBJECTS_SHAPE == 'bundle':
        # OTX-compatible shape: the STIX bundle at the top level with
        # more/next (no TAXII message envelope). Some consumers (e.g. the
        # OTX feed Vision One already ingests) expect this rather than the
        # spec envelope. Off by default; see taxii.objects_shape.
        body: Dict[str, Any] = {'type': 'bundle', 'objects': bundle.get('objects', [])}
        body['more'] = bool(more)
        if more and nxt:
            body['next'] = nxt
        return _taxii_response(body)

    return _taxii_response(
        _taxii_message(collection_id, bundle, more=more, next_cursor=nxt)
    )


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


def _collection_param(value: Any) -> Tuple[Optional[str], Optional[str]]:
    """Validate a ?collection= / body ``collection`` against the registry.

    Returns ``(collection_id, None)``, ``(None, None)`` when omitted, or
    ``(None, error)`` for an unknown collection id. An aggregate is accepted:
    it is a real collection that reads as the union of its members.
    """
    if value is None or value == '':
        return None, None
    cid = str(value)
    if cid not in TAXII_COLLECTION_MAP:
        return None, f'unknown collection: {cid!r}'
    return cid, None


def _collection_ids_for(cid: Optional[str]) -> List[str]:
    """The stored ``collection_id`` values a read of ``cid`` covers.

    An aggregate resolves to its members (the union); anything else to
    itself. An id that is blank, or unknown to the registry, resolves to
    itself too — callers validate first, and a stray id then matches nothing
    rather than silently widening to the whole feed.
    """
    if not cid:
        return []
    cfg = TAXII_COLLECTION_MAP.get(cid)
    if cfg is not None and cfg.members:
        return list(cfg.members)
    return [cid]


def _apply_collection_filter(query, cid: Optional[str]):
    """Restrict a STIXObject query to what a read of ``cid`` covers.

    A no-op for a blank id (every collection), an equality filter for one id
    and ``IN`` for an aggregate's union.
    """
    ids = _collection_ids_for(cid)
    if not ids:
        return query
    if len(ids) == 1:
        return query.filter(STIXObject.collection_id == ids[0])
    return query.filter(STIXObject.collection_id.in_(ids))


def _collection_write_target(value: Any) -> Tuple[Optional[str], Optional[str]]:
    """Resolve the collection a *write* targets.

    Omitted -> the manual collection (``gt_intel``). An aggregate is
    rejected: it owns no rows, so a write to it would land somewhere no
    reader of the aggregate would ever look. Returns ``(collection_id, None)``
    or ``(None, error)``.
    """
    if value is None or value == '':
        return DEFAULT_MANUAL_COLLECTION_ID, None
    cid = str(value)
    cfg = TAXII_COLLECTION_MAP.get(cid)
    if cfg is None:
        return None, f'unknown collection: {cid!r}'
    if cfg.members:
        return None, (
            f'collection {cid!r} is an aggregate (the union of '
            f'{", ".join(cfg.members)}); write to one of its members instead'
        )
    return cid, None


def _resolve_ingest_target(configured: Any, default: str) -> str:
    """Resolve a poller's configured ``ingest_collection`` to a writable leaf.

    A poller must never route community data into the aggregate or into an
    unknown id, so either falls back to ``default`` with a warning rather
    than failing the poll.
    """
    if configured is None or configured == '':
        return default
    cid = str(configured)
    cfg = TAXII_COLLECTION_MAP.get(cid)
    if cfg is None:
        logger.warning("ingest_collection %r is unknown; using %r", cid, default)
        return default
    if cfg.members:
        logger.warning(
            "ingest_collection %r is an aggregate (the union of %s); using %r",
            cid, ', '.join(cfg.members), default)
        return default
    return cid


@app.route('/feed', methods=['GET'])
def get_feed():
    """GET /feed — latest STIX feed in TAXII 2 XML format (authenticated).

    Optional ``?collection=<id>`` limits the feed to one collection
    (default: the primary collection).
    """
    if not _request_allowed():
        return _unauthorized_feed_response()

    cid, err = _collection_param(request.args.get('collection'))
    if err:
        return jsonify({'error': err}), 400
    cid = cid or TAXII_COLLECTION_ID

    session = create_session()
    try:
        q = session.query(STIXObject)
        q = _apply_collection_filter(q, cid)
        # Bounded like /objects: the XML feed is built in one response, so cap
        # how much a single request can materialise.
        q = q.order_by(STIXObject.modified.asc(), STIXObject.stix_id.asc())
        rows = q.limit(_MAX_OBJECTS_JSON + 1).all()
        db_objects = rows[:_MAX_OBJECTS_JSON]
        if len(rows) > _MAX_OBJECTS_JSON:
            logger.warning(
                "/feed truncating response at %d objects (cap %d)",
                _MAX_OBJECTS_JSON, _MAX_OBJECTS_JSON,
            )
    finally:
        session.close()

    # Rendered from the rows (DB is the source of truth), so an object can no
    # longer be dropped from the feed by a missing memory-store entry.
    bundles = [
        {
            'id': row.stix_id,
            'type': row.object_type,
            'object': _row_to_threat_intel(row).to_stix_object().get('object', {}),
        }
        for row in db_objects
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
    in the feed so entries can be reviewed before re-ingesting. Optional
    ``?collection=<id>`` limits the view to one collection (default: the
    primary collection).
    """
    if not _request_allowed():
        return jsonify({'error': 'Unauthorized'}), 401

    cid, err = _collection_param(request.args.get('collection'))
    if err:
        return jsonify({'error': err}), 400
    cid = cid or TAXII_COLLECTION_ID

    raw_limit = request.args.get('limit')
    limit = None
    if raw_limit not in (None, ''):
        try:
            limit = int(raw_limit)
            if limit <= 0:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({
                'error': f'limit must be a positive integer, got {raw_limit!r}'
            }), 400
    cap = _MAX_OBJECTS_JSON if limit is None else min(limit, _MAX_OBJECTS_JSON)

    session = create_session()
    try:
        q = session.query(STIXObject)
        q = _apply_collection_filter(q, cid)
        # Fetch one extra row so truncation is reported without a 2nd query.
        # (No ORDER BY: the cap is a size guard, and the previous unordered
        # read order is kept so the dashboard's list order is unchanged.)
        rows = q.limit(cap + 1).all()
        truncated = len(rows) > cap
        db_objects = rows[:cap]
    finally:
        session.close()

    objects = []
    for row in db_objects:
        # Render from the row so a missing memory entry can't hide an object.
        obj = _row_to_threat_intel(row)
        verdict = gate_verdict(obj, row)
        objects.append({
            'id': row.stix_id,
            'type': row.object_type,
            'value': (
                obj.ip_address
                or obj.domain
                or obj.hash_value
                or obj.value
                or obj.name
                or (f'{obj.source_ref} → {obj.relationship_type} → {obj.target_ref}'
                    if obj.object_type == 'relationship' else None)
            ),
            'labels': obj.labels or [],
            'confidence': row.confidence,
            # Scoring pipeline: the computed score, or None when the object was
            # never scored (manual intel, or scoring was off at ingest time).
            # Shown as "—" rather than 0 in the dashboard, so "unscored" is not
            # mistaken for "scored as badly as possible".
            'score': row.score,
            'source': verdict['source'],
            'gated': verdict['gated'],
            'gate_reason': verdict['reason'],
            'gate_reason_label': verdict['reason_label'],
            'revoked': bool(row.revoked),
            'revoked_at': row.revoked_at.isoformat() + 'Z' if row.revoked_at else None,
            'last_seen': row.last_seen.isoformat() + 'Z' if row.last_seen else None,
        })

    withheld_count = sum(1 for o in objects if o['gated'])
    if truncated:
        logger.warning("/objects truncating response at %d rows (cap %d)",
                       cap, _MAX_OBJECTS_JSON)
    return jsonify({
        'objects': objects,
        'count': len(objects),
        'served_count': len(objects) - withheld_count,
        'withheld_count': withheld_count,
        'truncated': truncated,
    }), 200


@app.route('/ui/stats', methods=['GET'])
def ui_stats():
    """GET /ui/stats — aggregate counts for the Intel graph dashboard.

    Optional ``?collection=<id>`` (default: primary) and
    ``?scope=community|manual|all`` (default ``community`` = every non-manual
    source: the OTX pull and any third-party TAXII pullers).
    """
    if not _request_allowed():
        return jsonify({'error': 'Unauthorized'}), 401

    cid, err = _collection_param(request.args.get('collection'))
    if err:
        return jsonify({'error': err}), 400
    cid = cid or TAXII_COLLECTION_ID
    scope = str(request.args.get('scope') or 'community').lower()
    if scope not in ('community', 'manual', 'all'):
        return jsonify({
            'error': f'scope must be community|manual|all, got {scope!r}'
        }), 400

    session = create_session()
    try:
        q = session.query(STIXObject)
        q = _apply_collection_filter(q, cid)
        rows = q.all()
    finally:
        session.close()

    by_type: Dict[str, int] = {}
    by_source: Dict[str, int] = {}
    reasons: Dict[str, int] = {}
    labels: Dict[str, int] = {}
    timeline: Dict[str, int] = {}
    conf_values: List[int] = []
    buckets = [0, 0, 0, 0, 0]          # 1-20, 21-40, 41-60, 61-80, 81-100
    total = served = withheld = revoked = 0

    with memory_lock:
        for row in rows:
            obj = memory_store.get(row.stix_id)
            if obj is None:
                continue
            src = row.source or 'manual'
            if scope == 'community' and src == 'manual':
                continue
            if scope == 'manual' and src != 'manual':
                continue
            total += 1
            by_type[row.object_type] = by_type.get(row.object_type, 0) + 1
            by_source[src] = by_source.get(src, 0) + 1
            if row.revoked:
                revoked += 1
            verdict = gate_verdict(obj, row)
            if verdict['gated']:
                withheld += 1
                key = verdict['reason'] or 'other'
                reasons[key] = reasons.get(key, 0) + 1
            else:
                served += 1
            for lb in (obj.labels or []):
                labels[lb] = labels.get(lb, 0) + 1
            if row.last_seen:
                day = row.last_seen.strftime('%Y-%m-%d')
                timeline[day] = timeline.get(day, 0) + 1
            c = int(row.confidence or 0)
            conf_values.append(c)
            buckets[min(4, max(0, (c - 1) // 20)) if c > 0 else 0] += 1

    def _ranked(counter: Dict[str, int], name: str) -> List[Dict[str, Any]]:
        return [{name: k, 'count': v}
                for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))]

    hist_labels = ['1-20', '21-40', '41-60', '61-80', '81-100']
    return jsonify({
        'collection': cid,
        'scope': scope,
        'total': total,
        'served': served,
        'withheld': withheld,
        'revoked': revoked,
        'sources': len(by_source),
        'categories': _ranked(by_type, 'type'),
        'by_source': _ranked(by_source, 'source'),
        'withheld_reasons': [
            {'reason': r, 'label': _GATE_REASON_LABELS.get(r, r), 'count': n}
            for r, n in sorted(reasons.items(), key=lambda kv: (-kv[1], kv[0]))
        ],
        'confidence': {
            'min': min(conf_values) if conf_values else 0,
            'max': max(conf_values) if conf_values else 0,
            'avg': round(sum(conf_values) / len(conf_values), 1) if conf_values else 0,
            'histogram': [{'bucket': hist_labels[i], 'count': buckets[i]}
                          for i in range(5)],
        },
        'timeline': [{'date': d, 'count': timeline[d]} for d in sorted(timeline)][-30:],
        'top_labels': _ranked(labels, 'label')[:10],
        'labels_total': sum(labels.values()),   # all label occurrences
        'generated': _stix_now(),
    }), 200


@app.route('/objects/<stix_id>/revoke', methods=['POST'])
def revoke_object(stix_id: str):
    """POST /objects/<stix_id>/revoke — revoke or reinstate an object.

    Body: {"action": "revoke"} (default) or {"action": "unrevoke"}. Revoking
    sets STIX ``revoked: true`` (still served, so clients drop it); unrevoking
    reinstates it. Revocation is the manual side of the indicator lifecycle.
    """
    if not _write_allowed():
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
            "Object %s %s (source=%s) by %s",
            stix_id, action, row.source, _actor(),
        )
        _audit(f'object.{action}', target=stix_id,
               collection=row.collection_id, detail=row.source)
        return jsonify({'id': stix_id, 'revoked': bool(row.revoked), 'changed': True})
    except Exception as exc:
        session.rollback()
        logger.error("Revoke error: %s", exc)
        return jsonify({'error': 'could not update the object'}), 500
    finally:
        session.close()


@app.route('/objects/<stix_id>/exclude', methods=['POST'])
def exclude_object(stix_id: str):
    """POST /objects/<stix_id>/exclude — keep an object out of the Vision One feed.

    The one-click false-positive filter: look the object up, derive its value,
    and record a benign entry so the gate withholds it (Vision One never sees
    it, so it cannot block legitimate traffic on it). Body is optional:
    ``{"kind": "exact|domain|cidr", "note": "..."}``. The default is ``domain``
    for a domain object — so a whole domain is excluded, not one host — and
    ``exact`` otherwise.
    """
    if not _write_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    session = create_session()
    try:
        row = session.query(STIXObject).filter_by(stix_id=stix_id).first()
        if row is None:
            return jsonify({'error': f'Object not found: {stix_id}'}), 404
        obj = _row_to_threat_intel(row)
        collection_id = row.collection_id
    finally:
        session.close()

    value = (obj.domain or obj.ip_address or obj.value
             or obj.hash_value or obj.name)
    if not value:
        return jsonify({'error': 'object has no single value to exclude'}), 400
    kind = str(data.get('kind') or '').lower()
    if kind not in _BENIGN_KINDS:
        kind = 'domain' if obj.object_type == 'domain-name' else 'exact'
    payload, err, created = _create_benign_value(value, kind, data.get('note'))
    if err:
        return jsonify({'error': err}), 400
    if created:
        load_benign_values()
        logger.info("Benign value %s (%s) added from object %s by %s",
                    payload['value'], payload['kind'], stix_id, _actor())
        _audit('benign.create', target=payload['value'],
               collection=collection_id, detail=f'kind={payload["kind"]}')
    return jsonify({**payload, 'id': stix_id, 'changed': created}), (
        201 if created else 200)


@app.route('/ui', methods=['GET'])
@app.route('/', methods=['GET'])
def web_ui():
    """GET / or /ui — simple web form for feeding intel (no curl needed)."""
    return send_from_directory(
        str(Path(__file__).parent), 'intel-ui.html'
    )


@app.route('/feed/ingest', methods=['POST'])
def ingest_data():
    """POST /feed/ingest — accept STIX 2.1 JSON objects into the feed.

    Optional JSON body field ``mode``:
      * ``'replace'`` (default, legacy) — wipe and rebuild the *manual* feed.
      * ``'merge'`` — upsert by STIX id: edits/labels/confidence are
        refreshed, new ids are added, everything else (including other
        sources) is preserved. This is what the web UI "Save changes" uses.

    Optional JSON body field ``collection``: target TAXII collection
    (default: the primary collection).
    """
    if not _request_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json(silent=True)
    if not data or not data.get('stix_objects'):
        return jsonify({'error': 'No valid data provided'}), 400

    stix_objects = data.get('stix_objects')
    if not isinstance(stix_objects, list):
        return jsonify({'error': 'stix_objects must be a list'}), 400

    mode = str(data.get('mode') or 'replace')
    if mode not in ('replace', 'merge'):
        return jsonify({'error': "mode must be 'replace' or 'merge'"}), 400

    cid, err = _collection_write_target(data.get('collection'))
    if err:
        return jsonify({'error': err}), 400
    if not _write_allowed():
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        count = ingest_objects(stix_objects, mode=mode, collection=cid)
    except Exception as exc:
        logger.error("Ingest error: %s", exc)
        return jsonify({'error': 'could not ingest the supplied objects'}), 500

    logger.info("Ingest via /feed/ingest: %d object(s) into '%s' (mode=%s) by %s",
                count, cid, mode, _actor())
    _audit('feed.ingest', target=cid, collection=cid, count=count,
           detail=f'mode={mode}')
    return jsonify({
        'message': 'Data ingested successfully',
        'mode': mode,
        'collection': cid,
        'objects_count': count,
    }), 200


@app.route('/feed/delete', methods=['POST'])
def delete_objects_data():
    """POST /feed/delete — delete the given STIX ids from the feed (any source).

    Body: {"ids": ["ipv4-addr--...", ...]}. Used by the web UI's
    "Purge selected" (drop the rows the user ticked) — per-row and
    full-feed removal are the × button and DELETE /feed/purge.
    """
    if not _write_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    ids = data.get('ids')
    if not isinstance(ids, list) or not ids:
        return jsonify({'error': "ids: non-empty list of STIX ids required"}), 400

    id_set = {str(i) for i in ids if i}
    session = create_session()
    try:
        with memory_lock:
            rows = session.query(STIXObject).filter(STIXObject.stix_id.in_(id_set)).all()
            deleted = [r.stix_id for r in rows]
            for r in rows:
                session.delete(r)
            for s in [s for s in memory_store if s in id_set]:
                memory_store.pop(s, None)
            session.commit()
    except Exception as exc:
        session.rollback()
        logger.error("Delete error: %s", exc)
        return jsonify({'error': 'could not delete the requested objects'}), 500
    finally:
        session.close()
    logger.info("Deleted %d object(s) via /feed/delete by %s",
                len(deleted), _actor())
    _audit('feed.delete', count=len(deleted),
           detail=('ids: ' + ', '.join(deleted[:10])) if deleted else None)
    return jsonify({'deleted': len(deleted), 'ids': deleted}), 200


@app.route('/feed/purge', methods=['DELETE'])
def purge_data():
    """DELETE /feed/purge — purge threat intelligence data.

    Without ``?collection=`` purges EVERYTHING (all collections, all
    sources — the documented legacy behavior). With ``?collection=<id>``
    only that collection's objects are removed (what the web UI sends, so
    "Purge all" can't wipe a sibling collection).
    """
    if not _request_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    cid, err = _collection_param(request.args.get('collection'))
    if err:
        return jsonify({'error': err}), 400
    if not _write_allowed():
        # Writes (ingest, purge, delete, revoke, community pull) are the
        # dashboard's job — TAXII credentials are read-only.
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        purged = purge_all(collection=cid)
    except Exception as exc:
        logger.error("Purge error: %s", exc)
        return jsonify({'error': 'could not purge the feed'}), 500
    logger.info("Purge via /feed/purge: %d object(s) from %s by %s",
                purged, f"'{cid}'" if cid else 'ALL collections', _actor())
    _audit('feed.purge', target=cid or 'ALL', collection=cid, count=purged,
           detail='all collections' if not cid else f"collection '{cid}'")
    if cid:
        return jsonify({
            'message': f"Collection '{cid}' purged successfully",
            'collection': cid,
            'purged': purged,
        }), 200
    return jsonify({'message': 'All data purged successfully', 'purged': purged}), 200


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
    principal = _principal()
    return jsonify({
        'authenticated': principal is not None,
        'user': (principal or {}).get('user'),
        # The role drives which controls the dashboard shows. It is only a
        # convenience: every permission is enforced server-side.
        'role': (principal or {}).get('role'),
        'can_write': _require_role('editor'),
        'can_admin': _require_role('admin'),
        'sso': sso_public_info(),
    }), 200


@app.route('/ui/login', methods=['POST'])
def ui_login():
    """POST /ui/login — authenticate to the dashboard, set a session cookie."""
    data = request.get_json(silent=True) or {}
    username = str(data.get('username') or '')
    password = str(data.get('password') or '')
    # Fail closed if nothing can authenticate anyone — otherwise a blank login
    # could match a blank credential.
    if not _ui_username and not _ui_password and not _any_ui_users():
        return jsonify({'error': 'Login not configured (UI_AUTH_USER/UI_AUTH_PASSWORD unset)'}), 503
    who = _check_ui_login(username, password)
    if who is None:
        return jsonify({'error': 'Invalid credentials'}), 401
    logger.info("Dashboard login: %s (role=%s)", who['user'], who['role'])
    # The principal does not exist yet on this request (the cookie is set in
    # the response), so identity is passed explicitly.
    _audit('auth.login', target=who['user'], actor=who['user'],
           role=who['role'],
           via='ui_auth' if who['src'] == 'static' else 'session',
           detail='local')
    resp = jsonify({'message': 'Logged in', 'user': who['user'],
                    'role': who['role']})
    resp.set_cookie(
        'taxii2_ui_session',
        _session_cookie(who['user'], who['src']),
        max_age=_ui_session_ttl,
        httponly=True,
        samesite='Lax',
        secure=True,
    )
    return resp, 200


@app.route('/ui/logout', methods=['POST'])
def ui_logout():
    """POST /ui/logout — clear the dashboard session cookie."""
    resp = jsonify({'message': 'Logged out'})
    resp.delete_cookie('taxii2_ui_session')
    return resp, 200


@app.route('/ui/collections', methods=['GET'])
def ui_collections():
    """GET /ui/collections — the TAXII collection registry (dashboard).

    ``manual`` / ``community`` tell the dashboard where a write lands without
    it having to hardcode ids: a write never targets an aggregate, so the UI
    routes an edit made while the union is selected to ``manual``.
    """
    if not _request_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    collections = [
        {
            'id': c.id,
            'title': c.title,
            'members': list(c.members),
            'aggregate': bool(c.members),
        }
        for c in TAXII_COLLECTIONS
    ]
    return jsonify({
        'collections': collections,
        'primary': TAXII_COLLECTION_ID,
        'manual': DEFAULT_MANUAL_COLLECTION_ID,
        'community': DEFAULT_COMMUNITY_COLLECTION_ID,
    }), 200


# ---------------------------------------------------------------------------
# API key management (dashboard)
# ---------------------------------------------------------------------------

_MAX_KEY_LABEL = 128
_MAX_KEY_EXPIRY_DAYS = 3650

# Audit window served to the dashboard: newest-first, bounded. The tab filters
# and pages this window client-side (like the Feed tab), so the server never
# streams an unbounded trail.
_DEFAULT_AUDIT_LIMIT = 200
_MAX_AUDIT_LIMIT = 1000


def _api_key_public(row: 'ApiKey') -> Dict[str, Any]:
    """Dashboard view of a key. Never includes the secret (only its prefix)."""
    return {
        'id': row.id,
        'label': row.label,
        'prefix': row.prefix,
        'collections': _parse_key_collections(row.collections),
        'types': _parse_key_object_types(row.types),
        'enabled': bool(row.enabled),
        'created': _stix_ts(row.created),
        'expires_at': _stix_ts(row.expires_at),
        'last_used_at': _stix_ts(row.last_used_at),
        'rate_limit': int(row.rate_limit or 0),
        'rate_window': int(row.rate_window or 0),
        'max_objects': int(row.max_objects or 0),
        'expired': bool(row.expires_at and row.expires_at <= datetime.utcnow()),
    }


def _validate_key_scope(value: Any) -> Tuple[Optional[List[str]], Optional[str]]:
    """Validate the requested collection scope: a non-empty list of known ids."""
    if not isinstance(value, (list, tuple)) or not value:
        return None, 'collections: select at least one collection'
    scope: List[str] = []
    for raw in value:
        cid = str(raw or '').strip()
        if not cid:
            continue
        if cid not in TAXII_COLLECTION_MAP:
            return None, f'unknown collection: {cid!r}'
        if cid not in scope:
            scope.append(cid)
    if not scope:
        return None, 'collections: select at least one collection'
    return scope, None


def _validate_key_types(value: Any) -> Tuple[Optional[List[str]], Optional[str]]:
    """Validate a key's object-type allow-list: a non-empty list of known types.

    The list is *required* (a key must declare its type scope) and every member
    must be a stored type (``_SUPPORTED_STIX_TYPES``). Unknown values are
    rejected so a typo can't create a key that silently serves nothing.
    """
    if not isinstance(value, (list, tuple)) or not value:
        return None, 'types: select at least one object type'
    types: List[str] = []
    for raw in value:
        t = str(raw or '').strip()
        if not t:
            continue
        if t not in _SUPPORTED_STIX_TYPES:
            return None, f'unknown object type: {t!r}'
        if t not in types:
            types.append(t)
    if not types:
        return None, 'types: select at least one object type'
    return types, None


def _parse_key_expiry(value: Any) -> Tuple[Optional[datetime], Optional[str]]:
    """``expires_days`` (positive int) -> an absolute expiry, or None = never."""
    if value is None or value == '':
        return None, None
    try:
        days = int(value)
    except (TypeError, ValueError):
        return None, f'expires_days must be a positive integer, got {value!r}'
    if days <= 0 or days > _MAX_KEY_EXPIRY_DAYS:
        return None, f'expires_days must be between 1 and {_MAX_KEY_EXPIRY_DAYS}'
    return datetime.utcnow() + timedelta(days=days), None


def _parse_key_rate(data: Dict[str, Any]) -> Tuple[int, int, Optional[str]]:
    """``(rate_limit, rate_window, error)``; a 0 limit means unlimited."""
    raw_limit = data.get('rate_limit')
    raw_window = data.get('rate_window')
    limit = 0
    if raw_limit not in (None, ''):
        try:
            limit = int(raw_limit)
        except (TypeError, ValueError):
            return 0, 0, f'rate_limit must be a non-negative integer, got {raw_limit!r}'
        if limit < 0:
            return 0, 0, 'rate_limit must be a non-negative integer'
    window = 60
    if raw_window not in (None, ''):
        try:
            window = int(raw_window)
        except (TypeError, ValueError):
            return 0, 0, f'rate_window must be a positive integer, got {raw_window!r}'
        if window <= 0:
            return 0, 0, 'rate_window must be a positive integer'
    return limit, window, None


def _parse_key_max_objects(value: Any) -> Tuple[Optional[int], Optional[str]]:
    """``(max_objects, error)`` for a key's per-response ceiling.

    ``None``/empty/0 means "inherit ``taxii.max_objects``". A positive value
    caps how many objects this key is ever handed in one response.

    This is a *delivery* ceiling, not a filter: it does not change which
    objects the key is entitled to see, only how many arrive per page. The
    client must follow ``more``/``next`` (or poll with ``added_after``) to
    advance — a client that ignores both would keep receiving the same first
    page of the (modified, stix_id) ordering.
    """
    if value in (None, ''):
        return None, None
    try:
        cap = int(value)
    except (TypeError, ValueError):
        return None, f'max_objects must be a non-negative integer, got {value!r}'
    if cap < 0:
        return None, 'max_objects must be a non-negative integer'
    return (cap or None), None


# ---------------------------------------------------------------------------
# Dashboard users (admin only)
# ---------------------------------------------------------------------------
# Multi-user dashboard logins with roles, replacing the single shared
# ui.auth pair for everyday use. The static pair is deliberately NOT stored
# here: it stays a break-glass admin, so a mistake in this table can never
# lock the operator out of their own server.

_MAX_USERNAME = 64
_MIN_PASSWORD_LEN = 12


def _parse_new_username(value: Any) -> Tuple[Optional[str], Optional[str]]:
    name = str(value or '').strip()
    if not name:
        return None, 'username is required'
    if len(name) > _MAX_USERNAME:
        return None, f'username must be at most {_MAX_USERNAME} characters'
    if not re.fullmatch(r'[A-Za-z0-9._@-]+', name):
        return None, 'username may contain only letters, digits and . _ @ -'
    return name, None


def _parse_new_password(value: Any) -> Tuple[Optional[str], Optional[str]]:
    password = str(value or '')
    if len(password) < _MIN_PASSWORD_LEN:
        return None, f'password must be at least {_MIN_PASSWORD_LEN} characters'
    return password, None


def _parse_role(value: Any) -> Tuple[Optional[str], Optional[str]]:
    role = str(value or '').strip().lower()
    if role not in ROLE_LEVELS:
        return None, f'role must be one of {", ".join(sorted(ROLE_LEVELS))}'
    return role, None


def _user_public(row: 'UIUser') -> Dict[str, Any]:
    """Dashboard view of a user. Never includes the password hash."""
    return {
        'id': row.id,
        'username': row.username,
        'role': str(row.role or DEFAULT_ROLE),
        'enabled': bool(row.enabled),
        'created': _stix_ts(row.created),
        'last_login_at': _stix_ts(row.last_login_at),
    }


def _audit_public(row: 'AuditEvent') -> Dict[str, Any]:
    """Dashboard view of one audit event (timestamps as STIX 'Z' strings)."""
    return {
        'id': row.id,
        'created': _stix_ts(row.created),
        'actor': row.actor,
        'role': row.role,
        'via': row.via,
        'ip': row.ip,
        'action': row.action,
        'target': row.target,
        'collection': row.collection,
        'count': row.count,
        'detail': row.detail,
    }


def _enabled_admin_count(session, exclude_id: Optional[str] = None) -> int:
    """Enabled admins, optionally ignoring one row.

    Guards the one unrecoverable mistake an admin can make here: removing the
    last way in. (The break-glass ui.auth pair would still work, but relying
    on that is not a plan.)
    """
    q = session.query(UIUser).filter(UIUser.enabled.is_(True),
                                     UIUser.role == 'admin')
    if exclude_id:
        q = q.filter(UIUser.id != exclude_id)
    return q.count()


@app.route('/ui/users', methods=['GET'])
def ui_users():
    """GET /ui/users — list dashboard users (admin only)."""
    if not _admin_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    session = create_session()
    try:
        rows = session.query(UIUser).order_by(UIUser.username.asc()).all()
        users = [_user_public(r) for r in rows]
    finally:
        session.close()
    return jsonify({
        'users': users,
        'roles': sorted(ROLE_LEVELS, key=lambda r: ROLE_LEVELS[r]),
        # Surfaced so the UI can explain why the static login still works.
        'bootstrap_configured': bool(_ui_username and _ui_password),
    }), 200


@app.route('/ui/audit', methods=['GET'])
def ui_audit():
    """GET /ui/audit — the mutation/login audit trail, newest first (admin).

    Bounded window (``?limit=``, default 200, hard cap 1000); the dashboard
    tab searches and pages it client-side. ``?action=`` / ``?actor=`` are
    exact-match filters — an unknown value simply matches nothing (200 with an
    empty list), it is not an error. A malformed ``limit`` is a 400.
    """
    if not _admin_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    raw_limit = request.args.get('limit')
    limit = _DEFAULT_AUDIT_LIMIT
    if raw_limit not in (None, ''):
        try:
            limit = int(raw_limit)
        except (TypeError, ValueError):
            return jsonify({
                'error': f'limit must be an integer, got {raw_limit!r}'
            }), 400
        if limit < 1:
            return jsonify({'error': 'limit must be at least 1'}), 400
        limit = min(limit, _MAX_AUDIT_LIMIT)
    session = create_session()
    try:
        query = session.query(AuditEvent)
        action = request.args.get('action')
        if action:
            query = query.filter(AuditEvent.action == action)
        actor = request.args.get('actor')
        if actor:
            query = query.filter(AuditEvent.actor == actor)
        # Fetch one extra to detect truncation without a second COUNT query.
        rows = (query.order_by(AuditEvent.created.desc(), AuditEvent.id.desc())
                .limit(limit + 1).all())
        truncated = len(rows) > limit
        events = [_audit_public(r) for r in rows[:limit]]
    finally:
        session.close()
    return jsonify({
        'events': events,
        'count': len(events),
        'limit': limit,
        'max_limit': _MAX_AUDIT_LIMIT,
        'truncated': truncated,
        'actions': list(AUDIT_ACTIONS),
        'generated': _stix_now(),
    }), 200


@app.route('/ui/users', methods=['POST'])
def ui_users_create():
    """POST /ui/users — create a dashboard user (admin only)."""
    if not _admin_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    username, err = _parse_new_username(data.get('username'))
    if err:
        return jsonify({'error': err}), 400
    password, err = _parse_new_password(data.get('password'))
    if err:
        return jsonify({'error': err}), 400
    role, err = _parse_role(data.get('role') or DEFAULT_ROLE)
    if err:
        return jsonify({'error': err}), 400
    session = create_session()
    try:
        if session.query(UIUser).filter_by(username=username).first():
            return jsonify({'error': f'user {username!r} already exists'}), 409
        row = UIUser(id=uuid.uuid4().hex, username=username,
                     password_hash=generate_password_hash(password),
                     role=role, enabled=True)
        session.add(row)
        session.commit()
        payload = _user_public(row)
    except Exception as exc:
        session.rollback()
        logger.error("Could not create dashboard user: %s", exc)
        return jsonify({'error': 'could not create the user'}), 500
    finally:
        session.close()
    logger.info("Dashboard user %r created (role=%s) by %s",
                username, role, _actor())
    _audit('user.create', target=username, detail=f'role={role}')
    return jsonify(payload), 201


@app.route('/ui/users/<user_id>', methods=['POST'])
def ui_users_update(user_id: str):
    """POST /ui/users/<id> — change a user's role, password or enabled flag."""
    if not _admin_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    session = create_session()
    try:
        row = session.query(UIUser).filter_by(id=user_id).first()
        if row is None:
            return jsonify({'error': 'user not found'}), 404
        if data.get('role') not in (None, ''):
            role, err = _parse_role(data.get('role'))
            if err:
                return jsonify({'error': err}), 400
            if (role != 'admin' and row.role == 'admin' and row.enabled
                    and _enabled_admin_count(session, exclude_id=row.id) == 0):
                return jsonify({'error': 'cannot demote the last enabled admin'}), 400
            row.role = role
        if 'enabled' in data and data.get('enabled') is not None:
            enabled = bool(data.get('enabled'))
            if (not enabled and row.role == 'admin' and row.enabled
                    and _enabled_admin_count(session, exclude_id=row.id) == 0):
                return jsonify({'error': 'cannot disable the last enabled admin'}), 400
            row.enabled = enabled
        if data.get('password'):
            password, err = _parse_new_password(data.get('password'))
            if err:
                return jsonify({'error': err}), 400
            row.password_hash = generate_password_hash(password)
        session.commit()
        payload = _user_public(row)
    except Exception as exc:
        session.rollback()
        logger.error("Could not update dashboard user: %s", exc)
        return jsonify({'error': 'could not update the user'}), 500
    finally:
        session.close()
    logger.info("Dashboard user %r updated (role=%s, enabled=%s) by %s",
                payload['username'], payload['role'], payload['enabled'],
                _actor())
    changed = [k for k in ('role', 'enabled', 'password')
               if data.get(k) not in (None, '')]
    _audit('user.update', target=payload['username'],
           detail='fields: ' + ','.join(changed) if changed else None)
    return jsonify(payload), 200


@app.route('/ui/users/<user_id>/delete', methods=['POST'])
def ui_users_delete(user_id: str):
    """POST /ui/users/<id>/delete — remove a dashboard user (admin only)."""
    if not _admin_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    session = create_session()
    try:
        row = session.query(UIUser).filter_by(id=user_id).first()
        if row is None:
            return jsonify({'error': 'user not found'}), 404
        if (row.role == 'admin' and row.enabled
                and _enabled_admin_count(session, exclude_id=row.id) == 0):
            return jsonify({'error': 'cannot delete the last enabled admin'}), 400
        username = row.username
        session.delete(row)
        session.commit()
    except Exception as exc:
        session.rollback()
        logger.error("Could not delete dashboard user: %s", exc)
        return jsonify({'error': 'could not delete the user'}), 500
    finally:
        session.close()
    logger.info("Dashboard user %r deleted by %s", username, _actor())
    _audit('user.delete', target=username)
    return jsonify({'message': f'user {username!r} deleted'}), 200


@app.route('/ui/keys', methods=['GET'])
def ui_keys():
    """GET /ui/keys — list API keys (prefixes only, never the secret)."""
    if not _admin_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    session = create_session()
    try:
        rows = session.query(ApiKey).order_by(ApiKey.created.desc()).all()
        keys = [_api_key_public(r) for r in rows]
    finally:
        session.close()
    return jsonify({
        'keys': keys,
        'collections': [
            {'id': c.id, 'title': c.title,
             'members': list(c.members), 'aggregate': bool(c.members)}
            for c in TAXII_COLLECTIONS
        ],
        # Canonical vocabulary for the dashboard's object-type checkboxes.
        'types': _all_key_object_types(),
        'primary': TAXII_COLLECTION_ID,
    }), 200


@app.route('/ui/keys', methods=['POST'])
def ui_keys_create():
    """POST /ui/keys — mint a key. The plaintext is returned exactly once."""
    if not _admin_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    label = str(data.get('label') or '').strip()
    if not label:
        return jsonify({'error': 'label is required'}), 400
    if len(label) > _MAX_KEY_LABEL:
        return jsonify({'error': f'label must be at most {_MAX_KEY_LABEL} characters'}), 400

    scope, err = _validate_key_scope(data.get('collections'))
    if err:
        return jsonify({'error': err}), 400
    types, err = _validate_key_types(data.get('types'))
    if err:
        return jsonify({'error': err}), 400
    expires_at, err = _parse_key_expiry(data.get('expires_days'))
    if err:
        return jsonify({'error': err}), 400
    rate_limit, rate_window, err = _parse_key_rate(data)
    if err:
        return jsonify({'error': err}), 400
    key_max_objects, err = _parse_key_max_objects(data.get('max_objects'))
    if err:
        return jsonify({'error': err}), 400

    plaintext, prefix, secret_hash = _generate_api_key()
    session = create_session()
    try:
        row = ApiKey(
            id=uuid.uuid4().hex,
            label=label,
            prefix=prefix,
            secret_hash=secret_hash,
            enabled=True,
            expires_at=expires_at,
            collections=json.dumps(scope),
            types=json.dumps(types),
            rate_limit=rate_limit or None,
            rate_window=rate_window if rate_limit else None,
            max_objects=key_max_objects,
        )
        session.add(row)
        session.commit()
        payload = _api_key_public(row)
    except Exception as exc:
        session.rollback()
        logger.error("Could not create API key: %s", exc)
        return jsonify({'error': 'could not create the API key'}), 500
    finally:
        session.close()
    # Log the prefix only — the secret must never reach the log.
    logger.info("API key %s created (label=%r, collections=%s, types=%s) by %s",
                prefix, label, ','.join(scope), ','.join(types), _actor())
    # Prefix only — the secret must never reach the audit trail either.
    _audit('key.create', target=prefix,
           detail=(f'label={label!r}, collections={",".join(scope)}, '
                   f'types={",".join(types)}'))
    payload['key'] = plaintext
    payload['message'] = ('Copy this key now — it is shown once and cannot be '
                          'retrieved again.')
    return jsonify(payload), 201


@app.route('/ui/keys/<key_id>/revoke', methods=['POST'])
def ui_key_revoke(key_id: str):
    """POST /ui/keys/<id>/revoke — disable a key (revocation is permanent)."""
    if not _admin_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    session = create_session()
    try:
        row = session.query(ApiKey).filter_by(id=key_id).first()
        if row is None:
            return jsonify({'error': f'Unknown API key: {key_id}'}), 404
        if not row.enabled:
            return jsonify({**_api_key_public(row), 'changed': False}), 200
        row.enabled = False
        session.commit()
        payload = _api_key_public(row)
    except Exception as exc:
        session.rollback()
        logger.error("Could not revoke API key: %s", exc)
        return jsonify({'error': 'could not revoke the API key'}), 500
    finally:
        session.close()
    logger.info("API key %s revoked by %s", payload['prefix'], _actor())
    _audit('key.revoke', target=payload['prefix'])
    return jsonify({**payload, 'changed': True}), 200


# ---------------------------------------------------------------------------
# Known-legitimate filter (dashboard)
# ---------------------------------------------------------------------------
# The dynamic half of the false-positive filter (the static half is
# intel_filter.benign_values / benign_domains / benign_cidrs in config.yaml). An
# entry names a legitimate value the community gate WITHHOLDS, so Vision One
# never sees it and cannot block legitimate traffic. Stored in `benign_values`
# and mirrored into memory by load_benign_values(); the gate reads the memory
# copy, never the table.

_BENIGN_NOTE_MAX = 200


def _benign_public(row: 'BenignValue') -> Dict[str, Any]:
    """Dashboard view of one benign entry."""
    return {
        'id': row.id,
        'value': row.value,
        'kind': str(row.kind or 'exact'),
        'note': row.note,
        'created': _stix_ts(row.created),
        'created_by': row.created_by,
    }


def _create_benign_value(value: Any, kind: Any, note: Any
                         ) -> Tuple[Optional[Dict[str, Any]], Optional[str], bool]:
    """Insert a benign entry (idempotent).

    Returns ``(payload, error, created)`` where ``created`` is False when an
    identical ``(value, kind)`` entry already existed.
    """
    kind = str(kind or 'exact').lower()
    if kind not in _BENIGN_KINDS:
        return None, 'kind must be one of exact|domain|cidr', False
    normalised, err = _normalise_benign(value, kind)
    if err:
        return None, err, False
    note_text = str(note or '').strip() or None
    if note_text and len(note_text) > _BENIGN_NOTE_MAX:
        note_text = note_text[:_BENIGN_NOTE_MAX]
    session = create_session()
    try:
        existing = (session.query(BenignValue)
                    .filter_by(value=normalised, kind=kind).first())
        if existing is not None:
            return _benign_public(existing), None, False
        row = BenignValue(id=uuid.uuid4().hex, value=normalised, kind=kind,
                          note=note_text, created_by=_actor())
        session.add(row)
        session.commit()
        return _benign_public(row), None, True
    except Exception as exc:
        session.rollback()
        logger.error("Could not create benign value: %s", exc)
        return None, 'could not create the benign entry', False
    finally:
        session.close()


@app.route('/ui/benign', methods=['GET'])
def ui_benign():
    """GET /ui/benign — the known-legitimate filter.

    Returns the dynamic dashboard entries plus the static config-file rules
    (read-only here — those are edited in ``config.yaml``).
    """
    if not _request_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    session = create_session()
    try:
        rows = (session.query(BenignValue)
                .order_by(BenignValue.created.desc()).all())
        items = [_benign_public(r) for r in rows]
    finally:
        session.close()
    return jsonify({
        'benign': items,
        'count': len(items),
        'kinds': list(_BENIGN_KINDS),
        'config': {
            'benign_values': sorted(FILTER_BENIGN_VALUES),
            'benign_domains': sorted(FILTER_BENIGN_DOMAINS),
            'benign_cidrs': [str(n) for n in FILTER_BENIGN_CIDRS],
        },
    }), 200


@app.route('/ui/benign', methods=['POST'])
def ui_benign_create():
    """POST /ui/benign — keep a legitimate value out of the Vision One feed.

    Body: ``{"value": str, "kind": "exact|domain|cidr", "note": str?}``.
    """
    if not _write_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    payload, err, created = _create_benign_value(
        data.get('value'), data.get('kind'), data.get('note'))
    if err:
        return jsonify({'error': err}), 400
    if created:
        load_benign_values()
        logger.info("Benign value %s (%s) added by %s",
                    payload['value'], payload['kind'], _actor())
        _audit('benign.create', target=payload['value'],
               detail=f'kind={payload["kind"]}')
    return jsonify({**payload, 'changed': created}), (201 if created else 200)


@app.route('/ui/benign/<benign_id>/delete', methods=['POST'])
def ui_benign_delete(benign_id: str):
    """POST /ui/benign/<id>/delete — resume serving a value again."""
    if not _write_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    session = create_session()
    try:
        row = session.query(BenignValue).filter_by(id=benign_id).first()
        if row is None:
            return jsonify({
                'error': f'Unknown benign entry: {benign_id}'
            }), 404
        value, kind = row.value, str(row.kind or 'exact')
        session.delete(row)
        session.commit()
    except Exception as exc:
        session.rollback()
        logger.error("Could not delete benign value: %s", exc)
        return jsonify({'error': 'could not delete the benign entry'}), 500
    finally:
        session.close()
    load_benign_values()
    logger.info("Benign value %s (%s) removed by %s", value, kind, _actor())
    _audit('benign.delete', target=value, detail=f'kind={kind}')
    return jsonify({'id': benign_id, 'value': value, 'kind': kind,
                    'deleted': True}), 200


@app.route('/ui/vt', methods=['GET'])
def ui_vt_status():
    """GET /ui/vt — VirusTotal integration status + cache/quota usage.

    Reports whether it is enabled/configured and how much of the free-tier
    budget (4/min, 500/day) has been spent in the last rolling 24h.
    """
    if not _request_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify(vt_client.status()), 200


@app.route('/ui/vt/lookup', methods=['POST'])
def ui_vt_lookup():
    """POST /ui/vt/lookup — one on-demand, cached VirusTotal lookup.

    The false-positive tie-breaker: ask VT about a single value and decide
    whether to Exclude it. Body: ``{"value": str, "kind"?: str, "force"?: bool}``
    — or ``{"object_id": stix_id}`` to derive the value from a stored object.
    ``force: true`` ignores a fresh cache entry. Write role required (it spends
    the shared quota and writes the cache).
    """
    if not _write_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    value = data.get('value')
    kind = data.get('kind')
    if not value and data.get('object_id'):
        session = create_session()
        try:
            row = session.query(STIXObject).filter_by(
                stix_id=str(data['object_id'])).first()
            if row is None:
                return jsonify({'error': f"Object not found: {data['object_id']}"}), 404
            obj = _row_to_threat_intel(row)
            value = (obj.domain or obj.ip_address or obj.value
                     or obj.hash_value or obj.name)
            if not kind:
                kind = _VT_KIND_BY_TYPE.get(obj.object_type)
        finally:
            session.close()
    result = vt_client.lookup(value, kind=kind, force=bool(data.get('force')))
    if result.get('error'):
        return jsonify(result), 400
    logger.info("VirusTotal lookup %s (%s) by %s: %s", result.get('value'),
                result.get('kind'), _actor(), result.get('verdict'))
    return jsonify(result), 200


@app.route('/community/pullers', methods=['GET'])
def community_pullers():
    """GET /community/pullers — status of all community sources (dashboard)."""
    if not _request_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({
        'pullers': ([otx_poller.status()]
                    + [p.status() for p in taxii_pullers]
                    + [abuse_ch_poller.status()]),
    }), 200


@app.route('/community/pull/<name>', methods=['POST'])
def community_pull(name: str):
    """POST /community/pull/<name> — run one pull cycle now ('Pull now').

    Optional ``limit`` (JSON body ``{"limit": N}`` or ``?limit=N``) caps how
    many objects this single cycle ingests, overriding the puller's
    configured cap (``max_indicators_per_poll`` / ``max_objects_per_poll``).
    """
    if not _write_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    body = request.get_json(silent=True) or {}
    raw = body.get('limit', request.args.get('limit'))
    limit = None
    if raw is not None and raw != '':
        try:
            limit = int(raw)
            if limit <= 0:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({
                'error': f'limit must be a positive integer, got {raw!r}'
            }), 400
    if name == 'otx':
        puller = otx_poller
    elif name == abuse_ch_poller.STATE_ID:
        puller = abuse_ch_poller
    else:
        puller = next((p for p in taxii_pullers if p.name == name), None)
    if puller is None:
        return jsonify({'error': f'Unknown puller: {name}'}), 404
    result = puller.pull_now(limit=limit)
    if limit is not None:
        result['limit'] = limit
    if result.get('error') and 'misconfigured' in result['error']:
        return jsonify(result), 400
    logger.info("Community pull '%s' by %s: %s", name, _actor(),
                result.get('added', result.get('error', 'ok')))
    added = result.get('added')
    _audit('community.pull', target=name,
           count=added if isinstance(added, int) else None,
           detail=(f"error: {result['error']}" if result.get('error') else 'ok'))
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
                    'abuse_ch': _poller_state(abuse_ch_poller),
                },
                'virus_total': {
                    'enabled': vt_client.enabled,
                    'configured': vt_client.configured,
                    'quota_used_24h': vt_client.quota_used(),
                    'daily_limit': vt_client.daily_limit,
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
_URL_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://\S+$')
_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
_MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$')
_ASN_RE = re.compile(r'^AS\d+$', re.IGNORECASE)


def _guess_object_type(value: str) -> Tuple[str, Optional[str]]:
    """Guess (stix_type, hash_algorithm) for a raw value."""
    if _IPV4_RE.match(value):
        return 'ipv4-addr', None
    if ':' in value:
        try:
            if ipaddress.ip_address(value).version == 6:
                return 'ipv6-addr', None
        except ValueError:
            pass
    if _URL_RE.match(value):
        return 'url', None
    if _EMAIL_RE.match(value):
        return 'email-addr', None
    if _MAC_RE.match(value):
        return 'mac-addr', None
    if _HASH_RE.match(value):
        algos = {32: 'md5', 40: 'sha1', 64: 'sha256'}
        algo = algos.get(len(value))
        if algo:
            return 'file-hash', algo
    if _DOMAIN_RE.match(value):
        return 'domain-name', None
    if _ASN_RE.match(value):
        return 'autonomous-system', None
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


def _classify_value_cell(cell: str, role: str
                         ) -> Optional[Tuple[str, str, Optional[str]]]:
    """Classify one data cell into (value, stix_type, hash_algo), or None
    when the cell is not a valid value for its column role.

    ``role`` comes from header fuzzy-mapping ('ip' / 'domain' / 'hash' /
    'indicator'). Shape-validated; an 'indicator' column that actually
    holds a URL / email / ipv6 / MAC / ASN is promoted to that STIX type.
    """
    if role == 'ip':
        if _is_valid_ipv4(cell):
            return cell, 'ipv4-addr', 'ipv4'
        try:
            if ipaddress.ip_address(cell).version == 6:
                return cell, 'ipv6-addr', 'ipv6'
        except ValueError:
            pass
        return None
    if role == 'domain':
        if _DOMAIN_RE.match(cell):
            return cell, 'domain-name', 'domain'
        return None
    if role == 'hash':
        if (re.fullmatch(r'[0-9a-fA-F]+', cell)
                and len(cell) in _HASH_LEN_ALGO):
            return cell.lower(), 'file-hash', _guess_hash_algo(cell)
        return None
    # role == 'indicator': free text; promote recognizable shapes to their
    # STIX type (url / email-addr / ipv6-addr / mac-addr / autonomous-system).
    guessed, algo = _guess_object_type(cell)
    if guessed in ('url', 'email-addr', 'ipv6-addr', 'mac-addr',
                   'autonomous-system'):
        return cell, guessed, algo
    return cell, 'indicator', 'indicator'


def _parse_tabular_rows(fieldnames: List[str], rows: List[Dict[str, Any]],
                        start_row: int = 2
                        ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """The shared CSV / XLSX row parser.

    ``fieldnames`` are the header cells; ``rows`` are dict rows keyed by
    header. Headers are fuzzy-mapped to column roles; values are validated
    and typed by shape (see :func:`_classify_value_cell`). Returns STIX
    ingest payloads ready for ``ingest_objects(..., source='manual')`` plus
    the list of skipped rows.
    """
    if not rows or not fieldnames:
        return [], [{'error': 'empty file (no header row found)'}]

    # Resolve column roles from the header row. A role may span several
    # columns (e.g. both "src_ip" and "dst_ip"); each recognized column is
    # remembered and the row loop takes the first valid value per role.
    roles: Dict[str, str] = {}
    for h in fieldnames:
        role = _csv_classify_header(h)
        if role != 'ignore':
            roles[h] = role

    objects: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    # Emit one object per recognizable value column in a row (a row can carry
    # both an IP and a domain).
    value_roles = ('ip', 'domain', 'hash', 'indicator')
    for idx, raw in enumerate(rows, start=start_row):  # row 1 = header
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
                except (TypeError, ValueError):
                    pass

        emitted = False
        for vrole in value_roles:
            for h, r2 in roles.items():
                if r2 != vrole:
                    continue
                cell = (raw.get(h) or '').strip()
                if not cell:
                    continue
                parsed = _classify_value_cell(cell, vrole)
                if parsed is None:
                    continue
                value, otype, algo = parsed
                if otype == 'ipv4-addr':
                    obj_id = 'ipv4-addr--' + value.replace('.', '-')
                    obj = {'ipv4-addr': {'value': value}}
                elif otype == 'domain-name':
                    obj_id = 'domain-name--' + value.replace('.', '-')
                    obj = {'domain-name': {'value': value}}
                elif otype == 'file-hash':
                    obj_id = 'file-hash--' + value[:16]
                    obj = {'hash_value': {'algorithm': algo, 'value': value}}
                elif otype in ('url', 'email-addr', 'ipv6-addr', 'mac-addr',
                               'autonomous-system'):
                    stable = uuid.uuid5(uuid.NAMESPACE_OID, value).hex[:16]
                    obj_id = f'{otype}--{stable}'
                    if otype == 'autonomous-system':
                        # STIX wants the bare AS number, not the 'AS' prefix.
                        obj = {'autonomous-system': {
                            'number': int(re.sub(r'[^0-9]', '', value))}}
                    else:
                        obj = {otype: {'value': value}}
                else:
                    # Free-text indicator: slug the value so the STIX id
                    # stays valid ([A-Za-z0-9-]+ per spec) — free text can
                    # contain spaces/slashes that would fail id validation.
                    slug = re.sub(r'[^A-Za-z0-9-]', '-', value)[:16]
                    obj_id = 'indicator--' + slug
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


def parse_csv_intel(text: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Parse CSV text into (stix_objects, skipped_rows).

    Headers are fuzzy-mapped; values are validated (IPv4/IPv6 octets,
    domain shape, hash length) and re-classified when needed. Returns STIX
    ingest payloads ready for ``ingest_objects(..., source='manual')``.
    """
    try:
        reader = csv.DictReader(io.StringIO(text or ''))
        rows = []
        truncated = False
        for row in reader:
            if len(rows) >= _MAX_IMPORT_ROWS:
                truncated = True
                break
            rows.append(row)
    except Exception:
        return [], [{'error': 'could not parse CSV'}]

    if not rows or not reader.fieldnames:
        return [], [{'error': 'empty CSV (no header row found)'}]
    objects, skipped = _parse_tabular_rows(reader.fieldnames, rows, start_row=2)
    if truncated:
        skipped.append({
            'error': f'stopped after {_MAX_IMPORT_ROWS} rows '
                     f'(file contains more)'})
    return objects, skipped


def parse_xlsx_intel(data: bytes) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Parse an .xlsx workbook into (stix_objects, skipped_rows).

    The first row is the header (fuzzy-mapped like CSV); values are typed
    by shape. Requires ``openpyxl`` (an optional dependency — the server
    boots without it; only this path needs it).
    """
    try:
        from openpyxl import load_workbook
    except ImportError:
        return [], [{'error': 'openpyxl is not installed (pip install openpyxl)'}]
    try:
        wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
        ws = wb.active
        raw_rows = []
        truncated = False
        for row in ws.iter_rows(values_only=True):
            if len(raw_rows) >= _MAX_IMPORT_ROWS + 1:  # +1 = header row
                truncated = True
                break
            raw_rows.append(row)
        wb.close()
    except Exception as exc:
        # Don't echo the parser's message to the caller — it can name internal
        # zip members / paths. The detail stays in the server log.
        logger.error("XLSX parse error: %s", exc)
        return [], [{'error': 'could not parse workbook'}]
    if not raw_rows:
        return [], [{'error': 'empty workbook (no header row found)'}]

    headers: List[str] = []
    seen = set()
    for i, cell in enumerate(raw_rows[0]):
        h = str(cell).strip() if cell is not None else ''
        if not h:
            h = f'col_{i + 1}'
        while h in seen:  # dict keys must be unique
            h += '_'
        seen.add(h)
        headers.append(h)

    rows: List[Dict[str, Any]] = []
    for raw in raw_rows[1:]:
        rows.append({
            h: (str(cell).strip() if cell is not None else '')
            for h, cell in zip(headers, raw)
        })
    objects, skipped = _parse_tabular_rows(headers, rows, start_row=2)
    if truncated:
        skipped.append({
            'error': f'stopped after {_MAX_IMPORT_ROWS} rows '
                     f'(workbook contains more)'})
    return objects, skipped


@app.route('/feed/import-csv', methods=['POST'])
def import_csv_data():
    """POST /feed/import-csv — GT-team CSV / Excel (.xlsx) upload.

    Form field ``file`` (multipart; .csv or .xlsx) or raw CSV body.
    Merges in as ``source='manual'`` (append-only upsert — does NOT wipe
    existing rows), so the web UI "replace" semantics are not disturbed.
    """
    if not _request_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    filename = ''
    data_bytes: Optional[bytes] = None
    if 'file' in request.files:
        f = request.files['file']
        if not f or not f.filename:
            return jsonify({'error': 'no file provided'}), 400
        filename = (f.filename or '').lower()
        data_bytes = f.read()
    else:
        data_bytes = request.get_data()
    if not data_bytes or not data_bytes.strip():
        return jsonify({'error': 'empty file'}), 400

    if filename.endswith('.xlsx'):
        try:
            objects, skipped = parse_xlsx_intel(data_bytes)
        except Exception as exc:
            logger.error("XLSX import error: %s", exc)
            return jsonify({'error': 'could not parse the uploaded workbook'}), 400
        if skipped and any(
                'openpyxl' in (s.get('error') or '') for s in skipped[:1]):
            return jsonify({
                'imported': 0,
                'skipped': skipped[:1],
                'error': 'openpyxl is not installed (pip install openpyxl)',
            }), 500
    else:
        try:
            objects, skipped = parse_csv_intel(
                data_bytes.decode('utf-8-sig', errors='replace'))
        except Exception as exc:
            logger.error("CSV import error: %s", exc)
            return jsonify({'error': 'could not parse the uploaded CSV'}), 400
    if not objects:
        return jsonify({
            'imported': 0,
            'skipped': skipped[:50],
            'error': 'no recognizable rows (check headers/values)',
        }), 400
    # Import target collection: form/query field, default = the manual feed.
    cid, err = _collection_write_target(
        request.form.get('collection') or request.args.get('collection'))
    if err:
        return jsonify({'error': err}), 400
    if not _write_allowed():
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        added = ingest_objects(objects, mode='merge', source='manual',
                               collection=cid)
    except Exception as exc:
        logger.error("CSV ingest error: %s", exc)
        return jsonify({'error': 'could not import the uploaded file'}), 500
    logger.info("Import via /feed/import-csv: +%d object(s) into '%s' "
                "(source=manual, skipped %d) by %s",
                added, cid, len(skipped), _actor())
    _audit('feed.import', target=cid, collection=cid, count=added,
           detail=f'skipped {len(skipped)}')
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
        ingest_collection: comm_intel          # OUR collection to write into
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
        # Which of OUR collections this pull lands in. Deliberately NOT the
        # `collection` key — on a TAXII puller that one names the *upstream*
        # remote collection. A config pointing this at an aggregate is
        # ignored (with a warning) so community data can never be filed
        # under the union.
        self.ingest_collection = _resolve_ingest_target(
            self.config.get('ingest_collection'), DEFAULT_COMMUNITY_COLLECTION_ID)
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
        # Provenance label only — the `otx` source is already the object's
        # `source` tag (shown as the Source column in the UI), so it is not
        # duplicated as a label.
        labels = [pulse_ref]
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

    def _poll_once(self, limit: Optional[int] = None) -> int:
        """One poll cycle: fetch recent OTX pulses, map indicators, merge.

        ``limit`` caps the number of indicators ingested this cycle (an
        on-demand override for the dashboard's "Pull now"; the configured
        ``max_indicators_per_poll`` applies otherwise).
        Returns the number of objects ingested in this cycle.
        """
        if not self.base_url:
            logger.warning("OTX poller misconfigured (base_url missing)")
            return 0

        cap = int(limit) if limit and limit > 0 else self.max_indicators_per_poll
        # (descriptor, pulse) pairs: the pulse is carried alongside so the
        # scoring pipeline can use its metadata (age, adversary, size).
        candidates: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
        pulses_skipped = 0
        for pulse in self.fetch_recent_pulses():
            if len(candidates) >= cap:
                break
            pulse_id = pulse.get('id') or ''
            if not pulse_id:
                continue
            if int(pulse.get('indicator_count') or 0) < self.min_indicator_count:
                continue
            # Layer 2 (pulse metadata / age) before fetching the indicators —
            # deciding here also saves the per-pulse API call.
            if pulse_filter_reason(pulse):
                pulses_skipped += 1
                continue

            for item in self.fetch_pulse_indicators(pulse_id):
                stix = self.otx_indicator_to_stix(item, pulse.get('name') or '', 0)
                if stix:
                    candidates.append((stix, {
                        'source': 'otx',
                        'obs_key': f'pulse:{pulse_id}',
                        'pulse': pulse,
                        'raw_confidence': None,   # OTX has no per-IOC confidence
                    }))
                    if len(candidates) >= cap:
                        break

        accepted, quarantined, report, scores, observations = route_by_score(
            candidates)
        if report.get('enabled'):
            logger.info(
                "OTX scoring: %d candidate(s) -> %d accepted, %d quarantined; "
                "%d pulse(s) skipped by the metadata filter",
                report['candidates'], report['accepted'], report['quarantined'],
                pulses_skipped,
            )

        added = 0
        if accepted:
            added = ingest_objects(accepted, mode='merge', source=self.SOURCE,
                                   collection=self.ingest_collection,
                                   scores=scores)
        if quarantined:
            # Held in a collection the aggregate does not include, so it is
            # captured and reviewable in the dashboard but never served.
            ingest_objects(quarantined, mode='merge', source=self.SOURCE,
                           collection=SCORING_QUARANTINE_COLLECTION,
                           scores=scores)
        # Persist the sightings, including for quarantined objects: they are
        # what makes future cross-source corroboration possible.
        record_observations(observations)

        if not accepted and not quarantined:
            self.last_poll_at = datetime.utcnow()
            self.last_poll_added = 0
            save_puller_state('otx', 'ok', 0, 'no new indicators')
            return 0

        self.last_poll_at = datetime.utcnow()
        self.last_poll_added = added
        if report.get('enabled') and report['quarantined']:
            save_puller_state(
                'otx', 'ok', added,
                f'{added} served, {report["quarantined"]} quarantined '
                f'(score < {SCORING_THRESHOLD})')
        else:
            save_puller_state('otx', 'ok', added, f'{added} object(s) ingested')
        return added

    def status(self) -> Dict[str, Any]:
        """Dashboard status for the OTX puller."""
        st = read_puller_state('otx') or {}
        return {
            'name': 'AlienVault OTX',
            'id': 'otx',
            'kind': 'otx',
            'limit': self.max_indicators_per_poll,
            'enabled': self.enabled,
            'running': bool(self._thread and self._thread.is_alive()),
            'base_url': self.base_url,
            'ingest_collection': self.ingest_collection,
            'last_sync': st.get('last_sync'),
            'last_added': st.get('last_added', 0),
            'last_status': st.get('last_status'),
            'last_message': st.get('last_message'),
        }

    def pull_now(self, limit: Optional[int] = None) -> Dict[str, Any]:
        """Run one poll cycle synchronously (for the dashboard 'Pull now').

        ``limit`` overrides ``max_indicators_per_poll`` for this one cycle.
        """
        if not self.base_url:
            return {'name': 'AlienVault OTX', 'added': 0,
                    'error': 'misconfigured (base_url missing)'}
        try:
            added = self._poll_once(limit=limit)
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
# Covers the classic IOCs plus the extended SCOs, the UI-driven SDOs, and
# relationships, so a third-party pull preserves the full feed (graph edges
# included), not just flat indicators.
_STIX_TO_OUR_TYPE = {
    'ipv4-addr': 'ipv4-addr',
    'domain-name': 'domain-name',
    'file': 'file-hash',
    'indicator': 'indicator',
    'url': 'url',
    'email-addr': 'email-addr',
    'ipv6-addr': 'ipv6-addr',
    'mac-addr': 'mac-addr',
    'windows-registry-key': 'windows-registry-key',
    'autonomous-system': 'autonomous-system',
    'malware': 'malware',
    'threat-actor': 'threat-actor',
    'campaign': 'campaign',
    'relationship': 'relationship',
    'report': 'report',
    'identity': 'identity',
    'attack-pattern': 'attack-pattern',
    'vulnerability': 'vulnerability',
}
_HASH_ALGO_BY_STIX_KEY = {
    'MD5': 'md5', 'SHA-1': 'sha1', 'SHA-256': 'sha256', 'SHA-512': 'sha512',
}


def _stix21_object_to_our(o: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Map a raw STIX 2.1 object to an ingestable descriptor.

    Handles ipv4-addr / domain-name / file / indicator plus the extended
    SCOs (url, email-addr, ipv6-addr, mac-addr, windows-registry-key,
    autonomous-system), the SDOs (malware, threat-actor, campaign) and
    relationships. Returns None for unsupported/invalid objects.
    """
    stype = o.get('type')
    if stype not in _STIX_TO_OUR_TYPE:
        return None
    our_type = _STIX_TO_OUR_TYPE[stype]
    labels = list(o.get('labels') or [])
    confidence = int(o.get('confidence', 0) or 0) or 50

    if our_type == 'ipv4-addr':
        value = o.get('value')
        if not value or not _is_valid_ipv4(str(value)):
            return None
        payload = {'ipv4-addr': {'value': value}}
        stix_id = f"ipv4-addr--{str(value).replace('.', '-')}"
        name = None
    elif our_type == 'domain-name':
        value = o.get('value')
        if not value or not _DOMAIN_RE.match(str(value)):
            return None
        payload = {'domain-name': {'value': value}}
        stix_id = f"domain-name--{str(value).replace('.', '-')}"
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
        labels = [algo] + labels
        name = None
    elif our_type in ('url', 'email-addr', 'ipv6-addr', 'mac-addr'):
        value = o.get('value')
        if not value:
            return None
        if our_type == 'email-addr' and not _EMAIL_RE.match(str(value)):
            return None
        if our_type == 'ipv6-addr':
            try:
                if ipaddress.ip_address(str(value)).version != 6:
                    return None
            except ValueError:
                return None
        if our_type == 'mac-addr' and not _MAC_RE.match(str(value)):
            return None
        payload = {our_type: {'value': value}}
        stix_id = str(o.get('id') or '') or (
            f"{our_type}--{uuid.uuid5(uuid.NAMESPACE_OID, str(value)).hex}"
        )
        name = None
    elif our_type == 'windows-registry-key':
        value = o.get('key')
        if not value:
            return None
        payload = {'windows-registry-key': {'key': value}}
        stix_id = str(o.get('id') or '') or (
            'windows-registry-key--' + uuid.uuid5(
                uuid.NAMESPACE_OID, str(value)).hex
        )
        name = None
    elif our_type == 'autonomous-system':
        value = o.get('number')
        if value is None:
            return None
        payload = {'autonomous-system': {'number': value}}
        stix_id = str(o.get('id') or '') or (
            'autonomous-system--' + uuid.uuid5(
                uuid.NAMESPACE_OID, str(value)).hex
        )
        name = None
    elif our_type == 'relationship':
        source_ref = o.get('source_ref')
        rel_type = o.get('relationship_type')
        target_ref = o.get('target_ref')
        if not source_ref or not rel_type or not target_ref:
            return None
        payload = {'relationship': {
            'source_ref': source_ref,
            'relationship_type': rel_type,
            'target_ref': target_ref,
        }}
        stix_id = str(o.get('id') or '') or (
            'relationship--' + uuid.uuid5(
                uuid.NAMESPACE_OID, f'{source_ref}|{rel_type}|{target_ref}'
            ).hex
        )
        name = None
    elif our_type in ('malware', 'threat-actor', 'campaign',
                      'identity', 'attack-pattern', 'vulnerability'):
        name = o.get('name')
        if not name:
            return None
        payload = {our_type: {'name': name}}
        stix_id = str(o.get('id') or '') or (
            f"{our_type}--{uuid.uuid5(uuid.NAMESPACE_OID, str(name)).hex}"
        )
    elif our_type == 'report':
        name = o.get('name')
        refs = o.get('object_refs')
        if not name or not isinstance(refs, list) or not refs:
            return None
        payload = {'report': {'name': name, 'object_refs': refs}}
        stix_id = str(o.get('id') or '') or (
            'report--' + uuid.uuid5(uuid.NAMESPACE_OID, str(name)).hex
        )
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
        name = o.get('name')

    descriptor = {
        'id': stix_id,
        'type': our_type,
        'object': payload,
        'labels': labels or [],
        'confidence': confidence,
        'name': name,
    }
    # Preserve provenance/fidelity the upstream object carries.
    if o.get('description'):
        descriptor['description'] = o['description']
    upstream_vf = o.get('valid_from') or o.get('created')
    if upstream_vf:
        descriptor['valid_from'] = upstream_vf
    return descriptor


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
        collection: threat-intel         # UPSTREAM collection id to poll
        poll_interval: 300
        max_objects_per_poll: 5000
        ingest_collection: comm_intel    # OUR collection to write into
        enabled: true
    """

    KIND = 'taxii'

    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.name = str(self.config.get('name') or 'taxii').strip() or 'taxii'
        self.base_url = (self.config.get('base_url') or '').rstrip('/')
        self.username = self.config.get('username') or ''
        self.password = self.config.get('password') or ''
        # `collection` is the REMOTE (upstream) collection this puller reads.
        # Where the objects land on THIS server is `ingest_collection`.
        self.collection = (self.config.get('collection') or '').strip().lstrip('/')
        self.ingest_collection = _resolve_ingest_target(
            self.config.get('ingest_collection'), DEFAULT_COMMUNITY_COLLECTION_ID)
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

    def _fetch_objects(self, since: Optional[str],
                       limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Fetch STIX 2.1 objects from the configured collection (up to cap).

        Accepts both the spec TAXII envelope (``content.content.objects``) and
        the OTX-style bare bundle (``{type:"bundle", objects:[…]}``). ``limit``
        overrides ``max_objects_per_poll`` for this fetch.
        """
        if not self.collection:
            return []
        data = self._get_taxii(f'collections/{self.collection}/objects/', since)
        if not isinstance(data, dict):
            return []
        inner = (data.get('content') or {}).get('content')
        source = inner if isinstance(inner, dict) else data
        cap = int(limit) if limit and limit > 0 else self.max_objects_per_poll
        objects = source.get('objects') or []
        return [o for o in objects if isinstance(o, dict)][:cap]

    def _poll_once(self, limit: Optional[int] = None) -> Tuple[int, Optional[str]]:
        """One poll cycle: ?since= poll the collection, map, merge.

        ``limit`` caps the objects ingested this cycle (on-demand override).
        Returns (added, error_message_or_None).
        """
        if not self.base_url or not self.collection:
            return 0, 'misconfigured (base_url/collection missing)'

        since = _puller_since_iso(self.state_id)
        raw_objects = self._fetch_objects(since, limit=limit)
        if raw_objects is None:
            return 0, 'fetch failed (see server log)'

        stix_objects = [
            desc for desc in (_stix21_object_to_our(o) for o in raw_objects)
            if desc is not None
        ]
        # Scoring pipeline. A generic TAXII source has no pulse metadata, so
        # only the observation-derived signals apply; the upstream STIX
        # `confidence`, when present, is recorded as its raw_confidence.
        candidates = [(desc, {
            'source': self.name,
            'obs_key': 'remote:' + str(desc.get('id')
                                       or _indicator_value(desc)[0]),
            'raw_confidence': desc.get('confidence'),
            'pulse': None,
        }) for desc in stix_objects]
        accepted, quarantined, report, scores, observations = route_by_score(
            candidates)
        if report.get('enabled'):
            logger.info(
                "TAXII pull '%s' scoring: %d candidate(s) -> %d accepted, "
                "%d quarantined",
                self.name, report['candidates'], report['accepted'],
                report['quarantined'],
            )
        if not accepted and not quarantined:
            save_puller_state(self.state_id, 'ok', 0, 'no new objects')
            return 0, None

        added = 0
        if accepted:
            added = ingest_objects(accepted, mode='merge', source=self.name,
                                   collection=self.ingest_collection,
                                   scores=scores)
        record_observations(observations)
        if quarantined:
            ingest_objects(quarantined, mode='merge', source=self.name,
                           collection=SCORING_QUARANTINE_COLLECTION,
                           scores=scores)
        if report.get('enabled') and report['quarantined']:
            save_puller_state(
                self.state_id, 'ok', added,
                f'{added} served, {report["quarantined"]} quarantined '
                f'(score < {SCORING_THRESHOLD})')
        else:
            save_puller_state(self.state_id, 'ok', added,
                              f'{added} object(s) ingested')
        return added, None

    def pull_now(self, limit: Optional[int] = None) -> Dict[str, Any]:
        """Run one poll cycle synchronously (for the dashboard 'Pull now').

        ``limit`` overrides ``max_objects_per_poll`` for this one cycle.
        """
        added, err = self._poll_once(limit=limit)
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
            'id': self.name,
            'kind': self.KIND,
            'limit': self.max_objects_per_poll,
            'enabled': self.enabled,
            'running': bool(self._thread and self._thread.is_alive()),
            'base_url': self.base_url,
            'collection': self.collection,
            'ingest_collection': self.ingest_collection,
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
# abuse.ch HTTP puller (ThreatFox / Feodo Tracker / URLhaus)
# ---------------------------------------------------------------------------
# abuse.ch publishes no STIX/TAXII feed (their FAQ dropped it), so this is a
# native HTTP puller rather than a `taxii_pullers:` entry. One free Auth-Key
# (from auth.abuse.ch) covers all the JSON APIs.

_ABUSE_HASH_ALGOS = {
    'md5_hash': 'md5', 'md5': 'md5',
    'sha1_hash': 'sha1', 'sha1': 'sha1',
    'sha256_hash': 'sha256', 'sha256': 'sha256',
}


def _abuse_hash_descriptor(value: str, algo: str, confidence: int,
                           labels: List[str], description: str) -> Optional[Dict[str, Any]]:
    v = str(value or '').strip().lower()
    if not v or not _HASH_RE.match(v):
        return None
    return {
        'id': f'file-hash--{v[:16]}',
        'type': 'file-hash',
        'object': {'hash_value': {'algorithm': algo, 'value': v}},
        'labels': [algo] + list(labels),
        'confidence': confidence,
        'description': description,
    }


def _abuse_ioc_descriptor(raw_value: Any, ioc_type: str, confidence: Any,
                          labels: List[str],
                          description: str) -> Optional[Dict[str, Any]]:
    """Map one abuse.ch IOC to an ingestable STIX descriptor (or None).

    ``ioc_type`` is abuse.ch's own type string where known (ThreatFox:
    ``ip:port`` / ``domain`` / ``url`` / ``*_hash``); when it is blank the value
    shape is used instead (handy for URLhaus hosts, which can be an IP *or* a
    domain). Only IPv4 / domain / URL / md5 / sha1 / sha256 are consumed.
    """
    v = str(raw_value or '').strip()
    if not v:
        return None
    it = str(ioc_type or '').strip().lower()
    try:
        conf = int(confidence)
    except (TypeError, ValueError):
        conf = 50
    conf = max(0, min(100, conf))
    base = {'labels': list(labels), 'confidence': conf, 'description': description}

    algo = _ABUSE_HASH_ALGOS.get(it)
    if algo:
        return _abuse_hash_descriptor(v, algo, conf, list(labels), description)

    if it in ('ip:port', 'ip', 'ipv4'):
        ip = v.rsplit(':', 1)[0] if ':' in v else v
        if _is_valid_ipv4(ip):
            return {**base, 'id': f'ipv4-addr--{ip.replace(".", "-")}',
                    'type': 'ipv4-addr', 'object': {'ipv4-addr': {'value': ip}}}
        return None

    if it in ('domain', 'domain-name'):
        d = v.lower()
        if _DOMAIN_RE.match(d):
            return {**base, 'id': f'domain-name--{d.replace(".", "-")}',
                    'type': 'domain-name', 'object': {'domain-name': {'value': d}}}
        return None

    if it == 'url':
        if _URL_RE.match(v):
            return {**base, 'id': 'url--' + uuid.uuid5(uuid.NAMESPACE_OID, v).hex,
                    'type': 'url', 'object': {'url': {'value': v}}}
        return None

    # No usable type hint: infer from the value shape.
    guessed, g_algo = _guess_object_type(v)
    if guessed == 'ipv4-addr':
        return {**base, 'id': f'ipv4-addr--{v.replace(".", "-")}',
                'type': 'ipv4-addr', 'object': {'ipv4-addr': {'value': v}}}
    if guessed == 'domain-name':
        return {**base, 'id': f'domain-name--{v.replace(".", "-")}',
                'type': 'domain-name', 'object': {'domain-name': {'value': v}}}
    if guessed == 'url':
        return {**base, 'id': 'url--' + uuid.uuid5(uuid.NAMESPACE_OID, v).hex,
                'type': 'url', 'object': {'url': {'value': v}}}
    if guessed == 'file-hash':
        return _abuse_hash_descriptor(v, g_algo or 'sha256', conf,
                                      list(labels), description)
    return None


class AbuseChPuller:
    """Pulls community intel FROM abuse.ch (ThreatFox, Feodo Tracker, URLhaus).

    abuse.ch exposes no STIX/TAXII feed, so this fetches each configured feed's
    JSON API, maps the IOCs to our STIX descriptor shape, and merges them with
    ``source='abuse_ch'`` — independent of manual intel and subject to the
    community gate like any other community source.

    Config block (``abuse_ch:`` in config.yaml):
        enabled: false
        auth_key: '${ABUSE_CH_AUTH_KEY:-}'   # free from auth.abuse.ch
        feeds: [threatfox, feodo, urlhaus]
        poll_interval: 3600
        max_objects_per_poll: 5000
        threatfox_days: 1                    # ThreatFox window (get_iocs days)
        ingest_collection: comm_intel
    """

    SOURCE = 'abuse_ch'
    STATE_ID = 'abuse_ch'
    FEEDS = ('threatfox', 'feodo', 'urlhaus')
    LABEL = 'abuse.ch'

    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.auth_key = str(self.config.get('auth_key') or '').strip()
        # Absent `feeds:` -> all feeds; an explicit empty list -> none (so a
        # deployment can point the puller at nothing without deleting the block).
        raw_feeds = (self.config['feeds'] if 'feeds' in self.config
                     else list(self.FEEDS))
        self.feeds = [str(f).strip().lower() for f in raw_feeds
                      if str(f).strip().lower() in self.FEEDS]
        self.poll_interval = int(self.config.get('poll_interval', 3600))
        self.max_objects_per_poll = int(
            self.config.get('max_objects_per_poll', 5000))
        self.threatfox_days = int(self.config.get('threatfox_days', 1))
        self.ingest_collection = _resolve_ingest_target(
            self.config.get('ingest_collection'), DEFAULT_COMMUNITY_COLLECTION_ID)
        self.enabled = bool(self.config.get('enabled', False))
        self._stop = False
        self._thread: Optional[threading.Thread] = None
        self.last_poll_at: Optional[datetime] = None
        self.last_poll_added = 0

    def _headers(self) -> Dict[str, str]:
        headers = {
            'Accept': 'application/json',
            'User-Agent': 'TAXII-Server-AbuseCh-Puller/1.0',
        }
        if self.auth_key:
            headers['Auth-Key'] = self.auth_key
        return headers

    def _request_json(self, url: str, payload: Optional[Dict[str, Any]] = None) -> Optional[Any]:
        """GET (payload None) or POST (JSON payload) a URL; parsed body or None."""
        data = json.dumps(payload).encode('utf-8') if payload is not None else None
        req = urllib.request.Request(
            url, data=data, headers=self._headers(),
            method='POST' if data is not None else 'GET')
        if data is not None:
            req.add_header('Content-Type', 'application/json')
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as exc:
            logger.error("abuse.ch HTTP %s for %s", exc.code, url)
            return None
        except Exception as exc:
            logger.error("abuse.ch request failed for %s: %s", url, exc)
            return None

    @staticmethod
    def _threatfox_labels(row: Dict[str, Any]) -> List[str]:
        labels = ['threatfox']
        family = row.get('malware_printable') or row.get('malware')
        if family:
            labels.append(str(family))
        if row.get('threat_type'):
            labels.append(str(row['threat_type']))
        tags = row.get('tags') or []
        if isinstance(tags, list):
            labels.extend(str(t) for t in tags if t)
        return labels

    def fetch_threatfox(self) -> List[Dict[str, Any]]:
        """ThreatFox recent IOCs (carries a real ``confidence_level``)."""
        url = (self.config.get('threatfox_url')
               or 'https://threatfox-api.abuse.ch/api/v1/')
        data = self._request_json(
            url, {'query': 'get_iocs', 'days': self.threatfox_days})
        if not isinstance(data, dict):
            return []
        status = str(data.get('query_status') or '')
        if status and status != 'ok':
            logger.warning("ThreatFox query_status=%s", status)
            return []
        out: List[Dict[str, Any]] = []
        for row in (data.get('data') or []):
            if not isinstance(row, dict):
                continue
            desc = _abuse_ioc_descriptor(
                row.get('ioc'), row.get('ioc_type'), row.get('confidence_level'),
                self._threatfox_labels(row),
                'Pulled from abuse.ch ThreatFox'
                + (f" ({row.get('threat_type')})" if row.get('threat_type') else ''))
            if desc:
                out.append(desc)
        return out

    def fetch_feodo(self) -> List[Dict[str, Any]]:
        """Feodo Tracker botnet C2 IP blocklist (high-signal IPv4 C2)."""
        url = (self.config.get('feodo_url')
               or 'https://feodotracker.abuse.ch/downloads/ipblocklist.json')
        data = self._request_json(url)
        if not isinstance(data, list):
            return []
        out: List[Dict[str, Any]] = []
        for row in data:
            if not isinstance(row, dict):
                continue
            labels = ['feodo']
            if row.get('malware'):
                labels.append(str(row['malware']))
            if row.get('status'):
                labels.append(str(row['status']))
            desc = _abuse_ioc_descriptor(
                row.get('ip_address'), 'ip', 80, labels,
                'Pulled from abuse.ch Feodo Tracker'
                + (f" ({row.get('malware')})" if row.get('malware') else ''))
            if desc:
                out.append(desc)
        return out

    def fetch_urlhaus(self) -> List[Dict[str, Any]]:
        """URLhaus recent malicious URLs (+ their host, as a domain/IP)."""
        url = (self.config.get('urlhaus_url')
               or 'https://urlhaus-api.abuse.ch/v1/urls/recent/')
        data = self._request_json(url, {})
        if not isinstance(data, dict):
            return []
        out: List[Dict[str, Any]] = []
        for row in (data.get('urls') or []):
            if not isinstance(row, dict):
                continue
            labels = ['urlhaus']
            if row.get('threat'):
                labels.append(str(row['threat']))
            tags = row.get('tags') or []
            if isinstance(tags, list):
                labels.extend(str(t) for t in tags if t)
            desc = _abuse_ioc_descriptor(
                row.get('url'), 'url', 70, labels,
                'Pulled from abuse.ch URLhaus'
                + (f" ({row.get('url_status')})" if row.get('url_status') else ''))
            if desc:
                out.append(desc)
            # Also file the host (domain or IP) — the shape decides which.
            host_desc = _abuse_ioc_descriptor(
                row.get('host'), '', 70, list(labels),
                'Pulled from abuse.ch URLhaus (URL host)')
            if host_desc:
                out.append(host_desc)
        return out

    def _poll_once(self, limit: Optional[int] = None) -> int:
        """One poll cycle across the configured feeds (merge mode)."""
        cap = int(limit) if limit and limit > 0 else self.max_objects_per_poll
        fetchers = {
            'threatfox': self.fetch_threatfox,
            'feodo': self.fetch_feodo,
            'urlhaus': self.fetch_urlhaus,
        }
        candidates: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
        for feed in self.feeds:
            if len(candidates) >= cap:
                break
            fetcher = fetchers.get(feed)
            if fetcher is None:
                continue
            try:
                items = fetcher()
            except Exception as exc:
                logger.error("abuse.ch feed '%s' failed: %s", feed, exc)
                items = []
            logger.info("abuse.ch feed '%s' returned %s IOC(s)", feed, len(items))
            for item in items:
                # The feed name IS the source for corroboration: ThreatFox,
                # Feodo and URLhaus are independent sightings of the same
                # value, which is exactly what the score should reward.
                candidates.append((item, {
                    'source': feed,
                    'obs_key': feed + ':' + str(
                        item.get('id') or _indicator_value(item)[0]),
                    'raw_confidence': item.get('confidence'),
                    'pulse': None,
                }))
                if len(candidates) >= cap:
                    break

        if not candidates:
            self.last_poll_at = datetime.utcnow()
            self.last_poll_added = 0
            save_puller_state(self.STATE_ID, 'ok', 0, 'no new indicators')
            return 0

        # Same scoring/routing as the other community pullers. abuse.ch states
        # a real per-IOC confidence for ThreatFox, which is recorded as the
        # observation's raw_confidence and feeds the score.
        accepted, quarantined, report, scores, observations = route_by_score(
            candidates)
        if report.get('enabled'):
            logger.info(
                "abuse.ch scoring: %d candidate(s) -> %d accepted, "
                "%d quarantined",
                report['candidates'], report['accepted'],
                report['quarantined'])
        added = 0
        if accepted:
            added = ingest_objects(accepted, mode='merge', source=self.SOURCE,
                                   collection=self.ingest_collection,
                                   scores=scores)
        if quarantined:
            ingest_objects(quarantined, mode='merge', source=self.SOURCE,
                           collection=SCORING_QUARANTINE_COLLECTION,
                           scores=scores)
        record_observations(observations)
        self.last_poll_at = datetime.utcnow()
        self.last_poll_added = added
        if report.get('enabled') and report['quarantined']:
            save_puller_state(
                self.STATE_ID, 'ok', added,
                f'{added} served, {report["quarantined"]} quarantined '
                f'(score < {SCORING_THRESHOLD})')
        else:
            save_puller_state(self.STATE_ID, 'ok', added,
                              f'{added} object(s) ingested')
        return added

    def status(self) -> Dict[str, Any]:
        """Dashboard status for the abuse.ch puller."""
        st = read_puller_state(self.STATE_ID) or {}
        return {
            'name': 'abuse.ch',
            'id': self.STATE_ID,
            'kind': 'abuse_ch',
            'feeds': list(self.feeds),
            'limit': self.max_objects_per_poll,
            'enabled': self.enabled,
            'running': bool(self._thread and self._thread.is_alive()),
            'base_url': 'abuse.ch (ThreatFox / Feodo / URLhaus)',
            'ingest_collection': self.ingest_collection,
            'auth_key_set': bool(self.auth_key),
            'last_sync': st.get('last_sync'),
            'last_added': st.get('last_added', 0),
            'last_status': st.get('last_status'),
            'last_message': st.get('last_message'),
        }

    def pull_now(self, limit: Optional[int] = None) -> Dict[str, Any]:
        """Run one poll cycle synchronously (dashboard 'Pull now')."""
        if not self.feeds:
            return {'name': self.LABEL, 'added': 0,
                    'error': 'misconfigured (no feeds enabled)'}
        try:
            added = self._poll_once(limit=limit)
        except Exception as exc:
            save_puller_state(self.STATE_ID, 'error', 0, str(exc))
            return {'name': self.LABEL, 'added': 0, 'error': str(exc)}
        st = read_puller_state(self.STATE_ID) or {}
        return {
            'name': self.LABEL,
            'added': added,
            'error': None,
            'last_sync': st.get('last_sync'),
            'last_status': st.get('last_status'),
        }

    def start(self) -> None:
        """Start the background poller."""
        if self._thread and self._thread.is_alive():
            return
        self._stop = False
        self._thread = threading.Thread(
            target=self._poll_loop, name='AbuseChPuller', daemon=True)
        self._thread.start()
        logger.info(
            "abuse.ch puller started (interval=%ss, feeds=%s, auth_key=%s)",
            self.poll_interval, ','.join(self.feeds) or 'none',
            'set' if self.auth_key else 'MISSING')

    def stop(self) -> None:
        """Stop the background poller."""
        self._stop = True
        if self._thread:
            self._thread.join(timeout=5)
            logger.info("abuse.ch puller stopped")

    def _poll_loop(self) -> None:
        while not self._stop:
            try:
                count = self._poll_once()
                if count:
                    logger.info("abuse.ch poll ingested %s object(s)", count)
                else:
                    logger.info("abuse.ch poll complete (0 new objects)")
            except Exception as exc:
                logger.error("abuse.ch poll error: %s", exc)
            if not self._stop:
                time.sleep(self.poll_interval)


# ---------------------------------------------------------------------------
# VirusTotal — on-demand, cached enrichment (free tier; NOT a bulk gate)
# ---------------------------------------------------------------------------
# The free VT API is 4 req/min / 500 per day (and its ToS forbids commercial
# bulk use), so this never runs during a poll. It answers a single value on
# request, caches the verdict (vt_cache) and reuses it for cache_ttl seconds.
# It is a false-positive *tie-breaker*: a value VT calls clean is a good
# candidate for the known-legitimate filter.

_VT_KIND_BY_TYPE = {
    'ipv4-addr': 'ip', 'ipv6-addr': 'ip', 'domain-name': 'domain',
    'url': 'url', 'file-hash': 'hash',
}


def _vt_verdict(malicious: int, suspicious: int) -> str:
    if malicious:
        return 'malicious'
    if suspicious:
        return 'suspicious'
    return 'clean'


class VirusTotalClient:
    """On-demand VirusTotal lookups with a persistent, TTL'd cache.

    Config block (``virus_total:`` in config.yaml):
        enabled: false
        api_key: '${VIRUSTOTAL_API_KEY:-}'
        base_url: https://www.virustotal.com/api/v3
        cache_ttl: 86400     # reuse a cached verdict for this many seconds
        timeout: 20
        min_interval: 15     # seconds between outbound calls (free tier: 4/min)
        daily_limit: 500     # outbound calls per rolling 24h (free tier)
    """

    DEFAULT_BASE = 'https://www.virustotal.com/api/v3'

    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.enabled = bool(self.config.get('enabled', False))
        self.api_key = str(self.config.get('api_key') or '').strip()
        self.base_url = str(
            self.config.get('base_url') or self.DEFAULT_BASE).rstrip('/')
        self.cache_ttl = int(self.config.get('cache_ttl', 86400))
        self.timeout = int(self.config.get('timeout', 20))
        self.min_interval = float(self.config.get('min_interval', 15))
        self.daily_limit = int(self.config.get('daily_limit', 500))
        self._lock = threading.Lock()
        self._calls: List[datetime] = []   # outbound call timestamps (rolling 24h)

    @property
    def configured(self) -> bool:
        return bool(self.enabled and self.api_key)

    @staticmethod
    def _actor_safe() -> Optional[str]:
        """Best-effort actor label; safe to call outside a request context."""
        try:
            return _actor()
        except Exception:
            return 'system'

    # --- mapping helpers ---------------------------------------------------

    def _vt_kind(self, value: Any, kind: Any = None) -> Optional[str]:
        if kind:
            k = str(kind).strip().lower()
            if k in ('ip', 'domain', 'url', 'hash'):
                return k
            if k in _VT_KIND_BY_TYPE:
                return _VT_KIND_BY_TYPE[k]
        guessed, _algo = _guess_object_type(str(value))
        return _VT_KIND_BY_TYPE.get(guessed)

    def _endpoint(self, kind: str, value: str) -> str:
        if kind == 'ip':
            return f'{self.base_url}/ip_addresses/{urllib.parse.quote(value)}'
        if kind == 'domain':
            return f'{self.base_url}/domains/{urllib.parse.quote(value)}'
        if kind == 'hash':
            return f'{self.base_url}/files/{urllib.parse.quote(value)}'
        ident = base64.urlsafe_b64encode(
            value.encode('utf-8')).decode('ascii').rstrip('=')
        return f'{self.base_url}/urls/{ident}'

    def _gui_link(self, kind: str, value: str) -> str:
        if kind == 'ip':
            return f'https://www.virustotal.com/gui/ip-address/{value}'
        if kind == 'domain':
            return f'https://www.virustotal.com/gui/domain/{value}'
        if kind == 'hash':
            return f'https://www.virustotal.com/gui/file/{value}'
        ident = base64.urlsafe_b64encode(
            value.encode('utf-8')).decode('ascii').rstrip('=')
        return f'https://www.virustotal.com/gui/url/{ident}'

    # --- rate limiting -----------------------------------------------------

    def quota_used(self) -> int:
        """Outbound calls in the last rolling 24h (resets on restart)."""
        cutoff = datetime.utcnow() - timedelta(days=1)
        with self._lock:
            self._calls = [t for t in self._calls if t >= cutoff]
            return len(self._calls)

    def _rate_ok(self) -> Tuple[bool, Optional[float]]:
        """(allowed, wait_seconds). Records the call when allowed."""
        now = datetime.utcnow()
        cutoff = now - timedelta(days=1)
        with self._lock:
            self._calls = [t for t in self._calls if t >= cutoff]
            if len(self._calls) >= self.daily_limit:
                return False, None
            if self._calls:
                elapsed = (now - self._calls[-1]).total_seconds()
                if elapsed < self.min_interval:
                    return False, round(self.min_interval - elapsed, 1)
            self._calls.append(now)
        return True, None

    # --- cache -------------------------------------------------------------

    def _public(self, row: 'VtCache', cached: bool) -> Dict[str, Any]:
        return {
            'value': row.value,
            'kind': row.kind,
            'malicious': row.malicious or 0,
            'suspicious': row.suspicious or 0,
            'harmless': row.harmless or 0,
            'undetected': row.undetected or 0,
            'reputation': row.reputation,
            'categories': [c for c in str(row.categories or '').split(',') if c],
            'link': row.link,
            'verdict': _vt_verdict(row.malicious or 0, row.suspicious or 0),
            'fetched': row.fetched.isoformat() + 'Z' if row.fetched else None,
            'fetched_by': row.fetched_by,
            'cached': cached,
        }

    def _cache_get(self, key: str) -> Optional[Dict[str, Any]]:
        session = create_session()
        try:
            row = session.query(VtCache).filter_by(value=key).first()
            if row is None:
                return None
            age = (datetime.utcnow()
                   - (row.fetched or datetime.utcnow())).total_seconds()
            if age > self.cache_ttl:
                return None
            return self._public(row, cached=True)
        finally:
            session.close()

    def _cache_put(self, key: str, kind: str, parsed: Dict[str, Any],
                   actor: Optional[str]) -> Optional[Dict[str, Any]]:
        session = create_session()
        try:
            row = session.query(VtCache).filter_by(value=key).first()
            if row is None:
                row = VtCache(value=key)
                session.add(row)
            row.kind = kind
            row.malicious = int(parsed.get('malicious', 0) or 0)
            row.suspicious = int(parsed.get('suspicious', 0) or 0)
            row.harmless = int(parsed.get('harmless', 0) or 0)
            row.undetected = int(parsed.get('undetected', 0) or 0)
            row.reputation = parsed.get('reputation')
            row.categories = ','.join(parsed.get('categories') or []) or None
            row.link = parsed.get('link')
            row.fetched = datetime.utcnow()
            row.fetched_by = actor
            session.commit()
            return self._public(row, cached=False)
        except Exception as exc:  # pragma: no cover - persistence is best-effort
            session.rollback()
            logger.error("Could not cache VirusTotal result: %s", exc)
            return None
        finally:
            session.close()

    # --- HTTP --------------------------------------------------------------

    def _http_get(self, url: str) -> Tuple[int, Optional[Any]]:
        """GET JSON from VT. Returns (status_code, body); status 0 on error.

        A seam tests can stub without touching the network.
        """
        req = urllib.request.Request(
            url, headers={'Accept': 'application/json',
                          'x-apikey': self.api_key}, method='GET')
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as exc:
            return exc.code, None
        except Exception as exc:
            logger.error("VirusTotal request failed: %s", exc)
            return 0, None

    # --- the lookup --------------------------------------------------------

    def lookup(self, value: Any, kind: Any = None,
               force: bool = False) -> Dict[str, Any]:
        """Look up one value; serve a fresh cache hit, else call VT.

        Returns a dict with ``verdict``/counts on success, or ``{'error': ...}``.
        """
        raw = str(value or '').strip()
        if not raw:
            return {'error': 'value is required'}
        key = raw.lower()
        vt_kind = self._vt_kind(raw, kind)
        if not vt_kind:
            return {'error': 'unsupported value type: '
                             'need an IP, domain, URL or file hash'}

        if not force:
            hit = self._cache_get(key)
            if hit is not None:
                return hit

        if not self.configured:
            return {'error': 'VirusTotal is not configured '
                             '(set virus_total.enabled and api_key)',
                    'value': raw, 'kind': vt_kind}

        allowed, wait = self._rate_ok()
        if not allowed:
            if wait is None:
                msg = (f'VirusTotal daily limit reached '
                       f'({self.daily_limit} per 24h)')
            else:
                msg = f'VirusTotal rate limit — try again in {wait}s'
            return {'error': msg, 'value': raw, 'kind': vt_kind}

        url = self._endpoint(vt_kind, raw)
        status, body = self._http_get(url)
        if status == 404:
            parsed = {'malicious': 0, 'suspicious': 0, 'harmless': 0,
                      'undetected': 0, 'reputation': None, 'categories': [],
                      'link': self._gui_link(vt_kind, raw)}
            pub = self._cache_put(key, vt_kind, parsed, self._actor_safe())
            out = pub or {'value': raw, 'kind': vt_kind, **parsed,
                          'verdict': 'clean'}
            out['not_found'] = True
            out['cached'] = False
            return out
        if status == 0:
            return {'error': 'VirusTotal request failed (see server log)',
                    'value': raw, 'kind': vt_kind}
        if status >= 400:
            logger.error("VirusTotal HTTP %s for %s", status, url)
            return {'error': f'VirusTotal returned HTTP {status}',
                    'value': raw, 'kind': vt_kind}

        attrs = {}
        if isinstance(body, dict):
            attrs = ((body.get('data') or {}).get('attributes') or {})
        stats = attrs.get('last_analysis_stats') or {}
        cats = attrs.get('categories') or {}
        parsed = {
            'malicious': int(stats.get('malicious', 0) or 0),
            'suspicious': int(stats.get('suspicious', 0) or 0),
            'harmless': int(stats.get('harmless', 0) or 0),
            'undetected': int(stats.get('undetected', 0) or 0),
            'reputation': attrs.get('reputation'),
            'categories': sorted({str(c) for c in cats.values()})
            if isinstance(cats, dict) else [],
            'link': self._gui_link(vt_kind, raw),
        }
        pub = self._cache_put(key, vt_kind, parsed, self._actor_safe())
        if pub is not None:
            return pub
        return {'value': raw, 'kind': vt_kind, **parsed,
                'verdict': _vt_verdict(parsed['malicious'], parsed['suspicious']),
                'cached': False}

    def status(self) -> Dict[str, Any]:
        """Dashboard/config status for the VirusTotal integration."""
        session = create_session()
        try:
            entries = session.query(VtCache).count()
        except Exception:  # pragma: no cover
            entries = 0
        finally:
            session.close()
        return {
            'enabled': self.enabled,
            'configured': self.configured,
            'base_url': self.base_url,
            'cache_ttl': self.cache_ttl,
            'cache_entries': entries,
            'quota_used_24h': self.quota_used(),
            'daily_limit': self.daily_limit,
        }


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

# abuse.ch has no TAXII feed, so it gets its own native HTTP puller
# (ThreatFox / Feodo Tracker / URLhaus; one free Auth-Key).
abuse_ch_poller = AbuseChPuller(CONFIG.get('abuse_ch', {}) or {})

# VirusTotal on-demand enrichment (cached; free-tier rate aware).
vt_client = VirusTotalClient(CONFIG.get('virus_total', {}) or {})

# Initialize database tables at import time (endpoints and tests rely on it).
init_db()


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def start_background_jobs() -> None:
    """Restore persisted state, then start the TTL sweeper and pollers.

    These are in-process threads that must exist exactly ONCE per deployment.
    That is why the app is served by a single-process threaded server
    (waitress) and not by N WSGI *workers*: each gunicorn/uwsgi worker would
    import this module and start its own OTX/TAXII pullers and TTL sweeper,
    multiplying outbound pulls and auto-revocations.
    """
    # Restore ingested intel that persisted in the DB so the feed is complete
    # even on the first poll after a restart.
    rehydrate_memory()

    # Mirror the dashboard known-legitimate filter (benign_values) into memory
    # so the gate never queries the table on a poll.
    load_benign_values()

    # Auto-revoke any indicators that expired while the server was down,
    # then start the periodic TTL sweeper.
    sweep_expired_indicators()
    start_ttl_sweeper()

    # Bound the audit trail (only when a retention knob is set).
    start_audit_pruner()

    if otx_poller.enabled and otx_poller.base_url:
        otx_poller.start()
    for puller in taxii_pullers:
        if puller.enabled and puller.base_url and puller.collection:
            puller.start()
    if abuse_ch_poller.enabled and abuse_ch_poller.feeds:
        abuse_ch_poller.start()
    if self_check_poller.enabled and self_check_poller.base_url:
        self_check_poller.start()


def _serve(host: str, port: int, debug: bool, server_cfg: Dict[str, Any]) -> None:
    """Serve the app, using a production WSGI server unless debug/dev is asked.

    Werkzeug's ``app.run`` server is for development only. The default is
    waitress: a single-process, multi-threaded WSGI server, which preserves
    the one-process-owns-the-pollers model above while giving production-grade
    request handling. Set ``server.engine: flask`` (or ``server.debug: true``)
    to get the dev server back.
    """
    engine = str(server_cfg.get('engine', 'waitress') or 'waitress').lower()
    if debug or engine == 'flask':
        app.run(host=host, port=port, debug=debug)
        return
    try:
        from waitress import serve
    except ImportError:  # pragma: no cover - depends on the environment
        logger.warning(
            "waitress is not installed — falling back to the Flask/Werkzeug "
            "development server, which is NOT for production. "
            "Install it with `pip install waitress`."
        )
        app.run(host=host, port=port, debug=False)
        return
    threads = int(server_cfg.get('threads', 8) or 8)
    logger.info("Serving on %s:%s (waitress, threads=%s)", host, port, threads)
    serve(app, host=host, port=port, threads=threads, ident='TAXII/2.1')


def score_sample(limit: int = 100,
                 collection: Optional[str] = None) -> Dict[str, Any]:
    """Re-score a sample of stored intel and report what the pipeline would do.

    A backtest, not a live run: reads the database, makes no network calls and
    writes nothing. Answers "what would enabling this do to the feed I already
    have?" — which is a far more useful corpus than one fresh poll, since it
    contains the false positives that prompted the work.

    Returns a report dict; see :func:`_format_score_report` for the summary.
    """
    session = create_session()
    try:
        query = session.query(STIXObject)
        if collection:
            query = query.filter(STIXObject.collection_id == collection)
        # Manual intel is never scored (a human entered it), so it is excluded
        # rather than inflating the accept rate.
        query = query.filter(func.coalesce(STIXObject.source, 'manual') != 'manual')
        rows = query.order_by(STIXObject.modified.desc()).limit(int(limit)).all()
        # Plain Python here: func.coalesce is a SQL construct and cannot be
        # applied to already-materialised row values.
        values = [str(row.ip_address or row.domain or row.hash_value
                      or row.value or '') for row in rows]
        # Detach what we need before the session closes.
        sample = [(row.stix_id, row.object_type, value, row.source,
                   row.score_breakdown)
                  for row, value in zip(rows, values)]
    finally:
        session.close()

    # The real score now comes from observations (which know every source that
    # saw a value). Objects with no observations fall back to their stored
    # signal keys, then to the floor.
    summaries = observation_summaries([v for _, _, v, _, _ in sample if v])

    entries: List[Dict[str, Any]] = []
    rescored = 0
    for stix_id, obj_type, value, source, stored in sample:
        breakdown: Dict[str, int] = {}
        summary = summaries.get(_normalise_obs_value(value))
        if summary:
            # Exact: recomputed from the current observations and weights.
            _score, breakdown = score_from_summary(summary)
            rescored += 1
        elif stored:
            # Legacy object (scored before observations existed): the stored
            # breakdown keys are weight-independent, so re-scoring is exact.
            try:
                keys = json.loads(stored)
            except (TypeError, ValueError):
                keys = None
            if isinstance(keys, dict):
                breakdown = {k: SCORE_WEIGHTS.get(k, 0) for k in keys}
                rescored += 1
        if not breakdown:
            breakdown = score_from_summary(None)[1]
        score = max(0, min(100, sum(breakdown.values())))
        entries.append({
            'id': stix_id, 'value': value, 'type': obj_type, 'source': source,
            'outcome': 'accepted' if score >= SCORING_THRESHOLD else 'quarantined',
            'reason': None, 'score': score, 'breakdown': breakdown,
        })

    scored = [e['score'] for e in entries if e['score'] is not None]
    histogram = {f'{lo}-{lo + 19}': 0 for lo in range(0, 100, 20)}
    for score in scored:
        histogram[f'{min(score // 20 * 20, 80)}-{min(score // 20 * 20, 80) + 19}'] += 1
    return {
        'enabled': SCORING_ENABLED,
        'threshold': SCORING_THRESHOLD,
        'sampled': len(entries),
        'accepted': sum(1 for e in entries if e['outcome'] == 'accepted'),
        'quarantined': sum(1 for e in entries if e['outcome'] == 'quarantined'),
        'histogram': histogram,
        'avg_score': round(sum(scored) / len(scored), 1) if scored else None,
        'rescored_from_stored': rescored,
        'entries': entries,
    }


def _format_score_report(report: Dict[str, Any]) -> str:
    lines = [
        f"Scoring pipeline: {'ENABLED' if report['enabled'] else 'DISABLED'}"
        f"  (threshold {report['threshold']})",
        f"Sampled {report['sampled']} stored community object(s)",
        '',
        f"  accepted (served)               : {report['accepted']}",
        f"  quarantined (below threshold)   : {report['quarantined']}",
        f"  mean score                      : {report['avg_score']}",
        f"  re-scored from stored signals   : {report['rescored_from_stored']}"
        f" of {report['sampled']}",
        '',
        '  score distribution:',
    ]
    for band, count in report['histogram'].items():
        lines.append(f'    {band:>6} : {"#" * min(count, 60)} {count}')
    worst = sorted((e for e in report['entries'] if e['score'] is not None),
                   key=lambda e: e['score'])[:10]
    if worst:
        lines += ['', '  lowest-scoring (what quarantine would hold back):']
        for e in worst:
            lines.append(f"    {e['score']:3}  {e['type']:<14} {e['value']}"
                         f"   {','.join(f'{k}+{v}' for k, v in e['breakdown'].items())}")
    return '\n'.join(lines)


def main() -> None:
    """Application entry point.

    Note: Vision One is NOT started here. It is an external TAXII 2.1 client
    that polls /taxii2/ on its own (configured with taxii.auth). Only the
    optional background pollers start, and both are off by default.
    """
    parser = argparse.ArgumentParser(
        description='TAXII 2.1 server.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        '--score-sample', type=int, metavar='N',
        help='Backtest the scoring pipeline over N stored community objects '
             'and print the outcome, then exit. Reads only: no polling, no '
             'network calls, no writes. Use it to tune scoring.weights and '
             'scoring.threshold before enabling the pipeline.')
    parser.add_argument(
        '--score-collection', metavar='ID',
        help='Restrict --score-sample to one collection.')
    args = parser.parse_args()

    if args.score_sample is not None:
        if args.score_sample <= 0:
            parser.error('--score-sample must be a positive integer')
        print(_format_score_report(
            score_sample(args.score_sample, args.score_collection)))
        return

    start_background_jobs()

    server_cfg = CONFIG.get('server', {}) or {}
    _serve(
        str(server_cfg.get('host', '0.0.0.0')),
        int(server_cfg.get('port', 5000)),
        bool(server_cfg.get('debug', False)),
        server_cfg,
    )


if __name__ == '__main__':
    main()
