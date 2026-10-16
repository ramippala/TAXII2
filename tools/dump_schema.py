#!/usr/bin/env python3
"""Emit the TAXII server's database schema as SQL DDL.

The schema is defined once, by the SQLAlchemy models in ``server.py``
(``STIXObject``, ``Subscription``, ``ApiKey``, ``UIUser``, ``PullerState``,
``AuditEvent``), and
the app creates it automatically at startup — ``Base.metadata.create_all()`` in
``init_db()``, plus idempotent add-if-missing column migrations for databases
created by an older build. Nothing here is required to run the server.

This script exists so the DDL cannot drift from the code: it compiles the
*actual* models for a given dialect, for a DBA-managed deployment that must
pre-create the full schema (see IMPLEMENTATION_GUIDE.md → "Database Schema &
Production Setup") or for regenerating the DDL block in the docs.

Usage::

    python tools/dump_schema.py                      # PostgreSQL DDL (default)
    python tools/dump_schema.py --dialect sqlite
    python tools/dump_schema.py --dialect all        # sqlite + postgresql
    python tools/dump_schema.py > schema.sql         # logging goes to stderr
    python tools/dump_schema.py --check              # verify models still define
                                                     # the expected tables/indexes
    python tools/dump_schema.py --create             # create the schema in the
                                                     # configured database

``--create`` is the only mode that touches a real database; the others pin the
import to a throwaway SQLite file so dumping DDL never connects anywhere.

Only SQLite and PostgreSQL are offered: the models use unbounded ``VARCHAR``,
which PostgreSQL and SQLite accept but MySQL/MariaDB reject ("VARCHAR requires
a length on dialect mysql"). So the server cannot actually create its schema on
MariaDB/MySQL today — despite the guide once listing it — and generating DDL
that the app itself could not produce would be misleading.
"""

import argparse
import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# The tables the server is expected to define. Kept explicit so `--check` (and
# the test suite) catches a model that was dropped or renamed without the docs
# and migrations being updated alongside it.
EXPECTED_TABLES = (
    'stix_objects',
    'subscriptions',
    'api_keys',
    'ui_users',
    'puller_state',
    'audit_events',
    'benign_values',
)


def _load_metadata(force_memory_db: bool):
    """Import the app so the models register on ``Base.metadata``.

    Importing ``server`` runs ``init_db()``, so unless the caller wants to create
    the schema for real we point DATABASE_URL at a throwaway SQLite file first —
    dumping the DDL must never connect to (or mutate) a configured database.
    (A file, not ``sqlite://``: the in-memory form uses SingletonThreadPool,
    which rejects the ``pool_timeout`` the server's engine settings pass.)
    """
    if force_memory_db:
        os.environ['DATABASE_URL'] = 'sqlite:///' + os.path.join(
            tempfile.gettempdir(), 'taxii2-dump-schema.db')
    import server  # noqa: F401  (side effect: models registered on Base)
    return server


def _ddl_for(metadata, dialect_name: str) -> str:
    """Compile CREATE TABLE + CREATE INDEX for every model, for one dialect."""
    from sqlalchemy.dialects import postgresql, sqlite
    from sqlalchemy.schema import CreateIndex, CreateTable

    dialect = {
        'sqlite': sqlite.dialect,
        'postgresql': postgresql.dialect,
    }[dialect_name]()

    lines = [f'-- {dialect_name}', '']
    for table in metadata.sorted_tables:
        lines.append(str(CreateTable(table).compile(dialect=dialect)).strip() + ';')
        # Indexes are separate DDL; table.indexes covers both `index=True`
        # columns and the composite Index(...) objects in __table_args__.
        for index in sorted(table.indexes, key=lambda i: i.name or ''):
            lines.append(str(CreateIndex(index).compile(dialect=dialect)).strip() + ';')
        lines.append('')
    return '\n'.join(lines).rstrip() + '\n'


def _check(metadata) -> int:
    """Fail when the models no longer define the expected tables/indexes."""
    have = set(metadata.tables)
    missing = [t for t in EXPECTED_TABLES if t not in have]
    if missing:
        print(f'FAIL: models are missing tables: {", ".join(missing)}', file=sys.stderr)
        return 1
    if 'max_objects' not in metadata.tables['api_keys'].columns:
        print('FAIL: api_keys.max_objects is gone', file=sys.stderr)
        return 1
    if 'types' not in metadata.tables['api_keys'].columns:
        print('FAIL: api_keys.types (object-type allow-list) is gone',
              file=sys.stderr)
        return 1
    composite = {'ix_stix_objects_modified_id', 'ix_stix_objects_coll_modified_id'}
    have_idx = {i.name for t in metadata.tables.values() for i in t.indexes}
    missing_idx = sorted(composite - have_idx)
    if missing_idx:
        print(f'FAIL: missing poll-path indexes: {", ".join(missing_idx)}', file=sys.stderr)
        return 1
    print(f'OK: {len(have)} tables — {", ".join(sorted(have))}')
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--dialect', default='postgresql',
                        choices=['sqlite', 'postgresql', 'all'],
                        help='SQL dialect to emit (default: postgresql)')
    parser.add_argument('--check', action='store_true',
                        help='verify the models still define the expected schema')
    parser.add_argument('--create', action='store_true',
                        help='create the schema in the configured database '
                             '(the only mode that connects to a real DB)')
    args = parser.parse_args(argv)

    server = _load_metadata(force_memory_db=not args.create)

    if args.check:
        return _check(server.Base.metadata)

    if args.create:
        from sqlalchemy import inspect
        server.init_db()  # idempotent: create_all + add-if-missing migrations
        tables = sorted(inspect(server.engine).get_table_names())
        print(f'Schema ready on {server.DATABASE_URL.split("@")[-1]} '
              f'(backend={server.engine.dialect.name}): {", ".join(tables)}')
        return 0

    dialects = (['sqlite', 'postgresql'] if args.dialect == 'all'
                else [args.dialect])
    for name in dialects:
        print(_ddl_for(server.Base.metadata, name))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
