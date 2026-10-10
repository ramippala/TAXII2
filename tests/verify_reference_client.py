#!/usr/bin/env python3
"""Verify this TAXII 2.1 server with the OASIS *reference* client.

Trend Micro Vision One / XDR are TAXII 2.1 clients, so the authoritative way
to check "will a real client be able to fetch our feed?" without Vision One
itself is the official reference implementation, `taxii2-client`
(https://pypi.org/project/taxii2-client/).

NOTE: Cabby (https://cabby.readthedocs.io) is a TAXII **1.0/1.1** client and
cannot talk to a TAXII 2.1 server — do not use it for this server. This script
is the 2.1 equivalent.

Usage:
    pip install taxii2-client
    python tests/verify_reference_client.py

Configuration (env vars, with defaults for a stock local server):
    TAXII_URL                default http://localhost:5000/taxii2/
    TAXII_USER / TAXII_PASSWORD        primary collection credentials
    TAXII_COLLECTION         default threat-intel
    TAXII_PREMIUM_USER / TAXII_PREMIUM_PASSWORD   optional second-collection
                             credentials, to verify per-collection RBAC

Exit code is non-zero if any check fails, so it can gate a deploy.
"""
import os
import sys

try:
    import requests
    from taxii2client.v21 import ApiRoot, Collection
except ImportError:
    print('This script needs the reference client: pip install taxii2-client')
    raise SystemExit(2)

BASE = os.environ.get('TAXII_URL', 'http://localhost:5000/taxii2/')
USER = os.environ.get('TAXII_USER', 'admin')
PASSWORD = os.environ.get('TAXII_PASSWORD', 'admin')
COLLECTION = os.environ.get('TAXII_COLLECTION', 'threat-intel')
PREM_USER = os.environ.get('TAXII_PREMIUM_USER')
PREM_PASSWORD = os.environ.get('TAXII_PREMIUM_PASSWORD')

_failures = []


def check(label, ok, detail=''):
    mark = 'OK  ' if ok else 'FAIL'
    if not ok:
        _failures.append(label)
    print(f'  [{mark}] {label}' + (f' — {detail}' if detail else ''))


def envelope(msg):
    """Return the response as-is when it is a TAXII message envelope OR an
    OTX-style bare bundle; only wrap anything else."""
    if isinstance(msg, dict) and ('content' in msg or msg.get('type') == 'bundle'):
        return msg
    return {'object': 'message', 'content': {'content': msg}}


def objects(msg):
    env = envelope(msg)
    if env.get('type') == 'bundle':          # OTX-style bare bundle
        return env.get('objects', [])
    inner = (env.get('content') or {}).get('content') or {}
    if isinstance(inner, dict) and 'objects' in inner:
        return inner['objects']
    return []


def main():
    print(f'== Discovery / collections ==  ({BASE})')
    try:
        root = ApiRoot(BASE, user=USER, password=PASSWORD)
        title = root.title
        check('discover API root', bool(title), title)
        root.refresh_collections()
        visible = [c.id for c in root.collections]
        check(f'collection {COLLECTION!r} is readable', COLLECTION in visible, visible)
    except Exception as exc:  # noqa: BLE001
        check('discovery', False, f'{type(exc).__name__}: {exc}')
        return

    coll = Collection(f'{BASE.rstrip("/")}/collections/{COLLECTION}/',
                      user=USER, password=PASSWORD)

    print('== Get Objects ==')
    env = envelope(coll.get_objects())
    objs = objects(env)
    check('poll returns objects', bool(objs), f'{len(objs)} objects')
    if objs:
        # The server may return the spec TAXII envelope or (config
        # taxii.objects_shape: bundle) the OTX-style bare bundle.
        envelope_ok = (env.get('object') == 'message'
                       and (env.get('content') or {}).get('object') == 'content')
        bundle_ok = (env.get('type') == 'bundle' and 'objects' in env)
        check('response shape (spec envelope or OTX-style bundle)',
              envelope_ok or bundle_ok,
              'envelope' if envelope_ok else ('bundle' if bundle_ok else 'unexpected'))
        check('objects carry id/type/spec_version',
              all(all(k in o for k in ('id', 'type', 'spec_version')) for o in objs))
        check('spec_version is 2.1',
              all(o.get('spec_version') == '2.1' for o in objs))
        check('served objects are STIX 2.1 indicators (validated shape)',
              all(o.get('type') == 'indicator' and o.get('pattern') and o.get('valid_from')
                  for o in objs),
              f"{sum(1 for o in objs if o.get('type') == 'indicator')}/{len(objs)} indicators")

    print('== Filters (spec 5.3) ==')
    one_type = objects(coll.get_objects(type='domain-name'))
    check('match[type] single',
          all('[domain-name:value' in (o.get('pattern') or '') for o in one_type),
          f'{len(one_type)} domain-name indicators')
    ids = [o['id'] for o in objs[:2]]
    if len(ids) == 2:
        both = objects(coll.get_objects(id=ids))
        check('match[id] comma-separated list', len(both) == 2, f'{len(both)} of 2 ids')
    two = objects(coll.get_objects(type=['domain-name', 'ipv4-addr']))
    check('match[type] comma-separated list',
          all(any(k in (o.get('pattern') or '')
                  for k in ('[domain-name:', '[ipv4-addr:')) for o in two),
          f'{len(two)} indicators')
    delta = objects(coll.get_objects(added_after='2999-01-01T00:00:00Z'))
    check('added_after (future) is empty', len(delta) == 0, f'{len(delta)}')

    print('== Pagination (limit + next) ==')
    page1 = envelope(coll.get_objects(limit=5))
    p1 = objects(page1)
    check('limit honoured', len(p1) <= 5, f'{len(p1)} objects')
    if page1.get('more') and page1.get('next'):
        r = requests.get(coll.objects_url,
                         params={'limit': 5, 'next': page1['next']},
                         auth=(USER, PASSWORD),
                         headers={'Accept': 'application/taxii+json;version=2.1'},
                         timeout=15)
        page2 = r.json()
        p2 = objects(page2)
        check('next page fetched', len(p2) > 0, f'{len(p2)} objects')
        check('pages do not overlap', not (set(o['id'] for o in p1)
                                           & set(o['id'] for o in p2)))

    if PREM_USER and PREM_PASSWORD:
        print('== Per-collection RBAC ==')
        proot = ApiRoot(BASE, user=PREM_USER, password=PREM_PASSWORD)
        proot.refresh_collections()
        pvisible = [c.id for c in proot.collections]
        check('second principal sees its own collection',
              COLLECTION not in pvisible, pvisible)
        try:
            Collection(f'{BASE.rstrip("/")}/collections/{COLLECTION}/',
                       user=PREM_USER, password=PREM_PASSWORD).get_objects()
            check('cross-collection read denied', False, 'unexpectedly allowed')
        except Exception as exc:  # noqa: BLE001
            check('cross-collection read denied', True, type(exc).__name__)

    print()
    if _failures:
        print(f'FAILED: {len(_failures)} check(s): {_failures}')
        return 1
    print('All reference-client checks passed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
