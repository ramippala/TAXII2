#!/usr/bin/env python3
"""
Tests for TAXII Server Implementation
Tests all TAXII 2 endpoints, ingestion (replace + merge modes), auth,
Vision One integration, and the OTX community-intel puller.
"""

import sys
import os
import types
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from server import (
    app,
    ThreatIntel,
    generate_taxii_bundle,
    ingest_objects,
    memory_store,
    init_db,
    OtxPoller,
    VisionOnePoller,
)


def _reset_db():
    """Purge all feed rows (all sources) between tests."""
    import server
    session = server.create_session()
    try:
        memory_store.clear()
        session.query(server.STIXObject).delete()
        session.commit()
    finally:
        session.close()


def _manual_obj(value="192.168.1.100"):
    return {
        'id': f"ipv4-addr--{value.replace('.', '-')}",
        'type': 'ipv4-addr',
        'object': {'ipv4-addr': {'value': value}},
        'labels': ['threat'],
        'confidence': 90,
    }


def _otx_obj(value="8.8.8.8"):
    return {
        'id': f"ipv4-addr--{value.replace('.', '-')}",
        'type': 'ipv4-addr',
        'object': {'ipv4-addr': {'value': value}},
        'labels': ['otx', 'some-pulse'],
        'confidence': 70,
    }


def _row(last_seen=None, modified=None):
    """A minimal fake STIXObject row carrying the timestamps the gate uses."""
    r = types.SimpleNamespace()
    r.last_seen = last_seen
    r.modified = modified
    return r


class TestTaxiiServer(unittest.TestCase):
    """Test cases for TAXII server endpoints"""

    def setUp(self):
        """Set up test environment"""
        self.client = app.test_client()
        # Reset in-memory store + database so tests are isolated
        _reset_db()

        # Configure test TAXII auth credentials
        app.config['TAXII_AUTH'] = {
            'username': 'test_taxii_user',
            'password': 'test_taxii_pass',
        }
        self.test_auth_headers = {
            'X-Taxii-Username': 'test_taxii_user',
            'X-Taxii-Password': 'test_taxii_pass',
        }

    def _get_auth_headers(self):
        """Get auth headers for TAXII 2 requests (valid for data endpoints)."""
        return self.test_auth_headers

    def _ingest(self, stix_objects):
        """POST /feed/ingest with auth headers."""
        return self.client.post(
            '/feed/ingest',
            json={'stix_objects': stix_objects},
            headers=self._get_auth_headers(),
        )

    def test_health_check(self):
        """Test health check endpoint"""
        response = self.client.get('/health')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['status'], 'healthy')
        self.assertIn('objects_count', data)
        self.assertEqual(data['objects_count'], 0)

    def test_get_feed_empty(self):
        """Test feed endpoint with no objects (with auth)"""
        response = self.client.get('/feed', headers=self._get_auth_headers())
        self.assertEqual(response.status_code, 200)
        self.assertIn('Response', response.data.decode('utf-8'))

    def test_get_feed_no_auth(self):
        """Test feed endpoint without auth returns 401"""
        response = self.client.get('/feed')
        self.assertEqual(response.status_code, 401)

    def test_ingest_ip_address(self):
        """Test ingestion of IP address object"""
        response = self._ingest([
            {
                'id': 'ipv4-addr--123',
                'type': 'ipv4-addr',
                'object': {'ipv4-addr': {'value': '192.168.1.100'}},
                'labels': ['threat', 'malicious'],
                'confidence': 80,
            }
        ])
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['message'], 'Data ingested successfully')
        self.assertEqual(data['objects_count'], 1)

    def test_ingest_no_auth(self):
        """Test ingestion without auth returns 401"""
        response = self.client.post(
            '/feed/ingest',
            json={'stix_objects': [
                {'id': 'ipv4-addr--1', 'type': 'ipv4-addr',
                 'object': {'ipv4-addr': {'value': '1.2.3.4'}}}
            ]},
        )
        self.assertEqual(response.status_code, 401)

    def test_ingest_file_hash(self):
        """Test ingestion of file hash object"""
        response = self._ingest([
            {
                'id': 'file-hash--abcdef1234567890',
                'type': 'file-hash',
                'object': {
                    'hash_value': {
                        'algorithm': 'sha256',
                        'value': 'a' * 64,
                    }
                },
                'labels': ['sha256', 'malware'],
                'confidence': 75,
            }
        ])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['objects_count'], 1)

    def test_ingest_domain_name(self):
        """Test ingestion of domain name object"""
        response = self._ingest([
            {
                'id': 'domain-name--789',
                'type': 'domain-name',
                'object': {'domain-name': {'value': 'malicious.example.com'}},
                'labels': ['threat', 'malicious'],
                'confidence': 65,
            }
        ])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['objects_count'], 1)

    def test_ingest_indicator(self):
        """Test ingestion of indicator object"""
        response = self._ingest([
            {
                'id': 'indicator--abc',
                'type': 'indicator',
                'object': {'indicator': {'value': 'Suspicious Activity', 'labels': ['threat']}},
                'confidence': 90,
            }
        ])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['objects_count'], 1)

    def test_get_feed_after_ingest(self):
        """Test feed retrieval after ingestion (with auth)"""
        self._ingest([
            {
                'id': 'ipv4-addr--123',
                'type': 'ipv4-addr',
                'object': {'ipv4-addr': {'value': '192.168.1.100'}},
            }
        ])
        response = self.client.get('/feed', headers=self._get_auth_headers())
        self.assertEqual(response.status_code, 200)
        xml = response.data.decode('utf-8')
        self.assertIn('192.168.1.100', xml)

    def test_purge_data(self):
        """Test data purge endpoint"""
        self._ingest([
            {
                'id': 'ipv4-addr--123',
                'type': 'ipv4-addr',
                'object': {'ipv4-addr': {'value': '192.168.1.100'}},
            }
        ])
        response = self.client.delete('/feed/purge', headers=self._get_auth_headers())
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['message'], 'All data purged successfully')

        # Verify store is empty
        self.assertEqual(len(memory_store), 0)

    def test_purge_no_auth(self):
        """Test purge without auth returns 401"""
        response = self.client.delete('/feed/purge')
        self.assertEqual(response.status_code, 401)

    # ------------------------------------------------------------------
    # Web UI session auth
    # ------------------------------------------------------------------
    def test_ui_session_unauthenticated(self):
        """Test /ui/session reports not authenticated without a cookie."""
        response = self.client.get('/ui/session')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertFalse(data['authenticated'])
        self.assertIsNone(data['user'])

    def test_ui_login_success_sets_cookie(self):
        """Test /ui/login with correct ui.auth creds sets a session cookie."""
        # The UI creds come from ui.auth in config (default admin/admin in tests).
        import server
        user, pw = server._ui_username, server._ui_password
        response = self.client.post(
            '/ui/login',
            json={'username': user, 'password': pw},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.set_cookie)  # a session cookie was set
        # The session is now valid.
        session = self.client.get('/ui/session').get_json()
        self.assertTrue(session['authenticated'])
        self.assertEqual(session['user'], user)

    def test_ui_login_wrong_password(self):
        """Test /ui/login rejects a wrong password."""
        import server
        response = self.client.post(
            '/ui/login',
            json={'username': server._ui_username, 'password': 'wrong-password-xyz'},
        )
        self.assertEqual(response.status_code, 401)

    def test_ui_session_cookie_grants_data_access(self):
        """Test a valid UI session cookie can read /objects (no TAXII headers)."""
        import server
        user, pw = server._ui_username, server._ui_password
        login = self.client.post('/ui/login', json={'username': user, 'password': pw})
        cookie = None
        for k, v in login.headers:
            if k.lower() == 'set-cookie' and 'taxii2_ui_session' in v:
                cookie = v.split('=', 1)[1].split(';', 1)[0]
        self.assertIsNotNone(cookie, "login should set a session cookie")
        # Use the cookie directly (no X-Taxii-* headers) to read /objects.
        response = self.client.get(
            '/objects',
            headers={'Cookie': f'taxii2_ui_session={cookie}'},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('count', response.get_json())

    def test_ui_logout_clears_cookie(self):
        """Test /ui/logout clears the session cookie."""
        import server
        user, pw = server._ui_username, server._ui_password
        self.client.post('/ui/login', json={'username': user, 'password': pw})
        response = self.client.post('/ui/logout')
        self.assertEqual(response.status_code, 200)
        set_cookies = [v for k, v in response.headers if k.lower() == 'set-cookie']
        self.assertTrue(any('taxii2_ui_session=' in c for c in set_cookies))
        # After logout the session no longer authenticates.
        self.assertFalse(self.client.get('/ui/session').get_json()['authenticated'])

    def test_objects_accepts_session_or_taxii(self):
        """Test /objects accepts EITHER a session cookie OR TAXII headers."""
        import server
        # With TAXII headers (no cookie).
        r1 = self.client.get('/objects', headers=self._get_auth_headers())
        self.assertEqual(r1.status_code, 200)
        # With a session cookie (no headers).
        self.client.post('/ui/login', json={'username': server._ui_username, 'password': server._ui_password})
        r2 = self.client.get('/objects')
        self.assertEqual(r2.status_code, 200)

    def test_objects_rejects_no_creds(self):
        """Test /objects with neither cookie nor TAXII headers returns 401."""
        self.client.delete_cookie('taxii2_ui_session')
        response = self.client.get('/objects')
        self.assertEqual(response.status_code, 401)

    # ------------------------------------------------------------------
    # Third-party TAXII 2.1 puller
    # ------------------------------------------------------------------
    def test_stix21_object_mapping_ipv4(self):
        """Test STIX 2.1 ipv4-addr -> our descriptor."""
        import server
        d = server._stix21_object_to_our(
            {'type': 'ipv4-addr', 'value': '203.0.113.9', 'labels': ['c2'], 'confidence': 85})
        self.assertIsNotNone(d)
        self.assertEqual(d['type'], 'ipv4-addr')
        self.assertEqual(d['object']['ipv4-addr']['value'], '203.0.113.9')
        self.assertEqual(d['confidence'], 85)

    def test_stix21_object_mapping_domain(self):
        """Test STIX 2.1 domain-name -> our descriptor."""
        import server
        d = server._stix21_object_to_our({'type': 'domain-name', 'value': 'bad.example.com'})
        self.assertIsNotNone(d)
        self.assertEqual(d['type'], 'domain-name')
        self.assertEqual(d['object']['domain-name']['value'], 'bad.example.com')

    def test_stix21_object_mapping_file(self):
        """Test STIX 2.1 file (hashes) -> our file-hash descriptor."""
        import server
        d = server._stix21_object_to_our(
            {'type': 'file', 'hashes': {'SHA-256': 'b' * 64}})
        self.assertIsNotNone(d)
        self.assertEqual(d['type'], 'file-hash')
        self.assertEqual(d['object']['hash_value']['algorithm'], 'sha256')
        self.assertEqual(d['object']['hash_value']['value'], 'b' * 64)

    def test_stix21_object_mapping_indicator_pattern(self):
        """Test STIX 2.1 indicator (IP pattern) -> our ipv4 descriptor."""
        import server
        d = server._stix21_object_to_our({
            'type': 'indicator', 'pattern': "[ipv4-addr:value = '198.51.100.7']"})
        self.assertIsNotNone(d)
        # Pattern points at an IP -> mapped to ipv4-addr.
        self.assertEqual(d['type'], 'ipv4-addr')
        self.assertEqual(d['object']['ipv4-addr']['value'], '198.51.100.7')

    def test_stix21_object_mapping_unsupported(self):
        """Test unsupported/invalid STIX objects are dropped."""
        import server
        self.assertIsNone(server._stix21_object_to_our({'type': 'malware', 'name': 'x'}))
        self.assertIsNone(server._stix21_object_to_our({'type': 'ipv4-addr', 'value': '999.1.1.1'}))
        self.assertIsNone(server._stix21_object_to_our({'type': 'file'}))

    def test_taxii_puller_init(self):
        """Test TaxiiPuller initialization and URL building."""
        import server
        p = server.TaxiiPuller({
            'name': 'acme',
            'base_url': 'https://taxii.example.com/taxii2/',
            'username': 'u', 'password': 'p',
            'collection': 'feed1',
            'poll_interval': 120,
            'max_objects_per_poll': 10,
        })
        self.assertEqual(p.name, 'acme')
        self.assertEqual(p.base_url, 'https://taxii.example.com/taxii2')
        self.assertEqual(p.collection, 'feed1')
        self.assertEqual(p.max_objects_per_poll, 10)
        self.assertEqual(p.state_id, 'taxii:acme')
        self.assertFalse(p.enabled)
        # Basic auth header is built.
        self.assertIn('Authorization', p._headers('x'))
        self.assertEqual(p._headers('x')['Authorization'].startswith('Basic '), True)
        # API root url keeps the trailing slash.
        self.assertTrue(p._api_root_url().endswith('/'))

    def test_taxii_puller_misconfigured(self):
        """Test a puller missing base_url/collection reports misconfigured."""
        import server
        p = server.TaxiiPuller({'name': 'x'})
        added, err = p._poll_once()
        self.assertEqual(added, 0)
        self.assertIn('misconfigured', err)

    def test_taxii_puller_fetch_and_merge(self):
        """Test TaxiiPuller fetch + map + merge (with a stubbed _fetch_objects)."""
        import server
        _reset_db()
        p = server.TaxiiPuller({
            'name': 'testpull', 'base_url': 'https://x/taxii2', 'collection': 'c',
        })
        p._fetch_objects = lambda since: [
            {'type': 'ipv4-addr', 'value': '8.8.8.8', 'confidence': 60},
            {'type': 'domain-name', 'value': 'c2.example.com'},
            {'type': 'ipv4-addr', 'value': '10.1.1.1'},  # private -> still stored, gated
            {'type': 'malware', 'name': 'drop'},           # unsupported -> skipped
        ]
        added, err = p._poll_once()
        self.assertIsNone(err)
        self.assertEqual(added, 3)
        # They are stored with source='testpull'.
        session = server.create_session()
        try:
            rows = session.query(server.STIXObject).filter_by(source='testpull').all()
            vals = {r.ip_address or r.domain for r in rows}
        finally:
            session.close()
        self.assertEqual(vals, {'8.8.8.8', 'c2.example.com', '10.1.1.1'})
        # State was persisted.
        st = server.read_puller_state(p.state_id)
        self.assertEqual(st['last_status'], 'ok')
        self.assertEqual(st['last_added'], 3)

    def test_community_pullers_endpoint_requires_auth(self):
        """Test /community/pullers requires auth."""
        self.client.delete_cookie('taxii2_ui_session')
        response = self.client.get('/community/pullers')
        self.assertEqual(response.status_code, 401)
        # With TAXII headers it works and lists the OTX puller.
        r2 = self.client.get('/community/pullers', headers=self._get_auth_headers())
        self.assertEqual(r2.status_code, 200)
        names = [p['name'] for p in r2.get_json()['pullers']]
        self.assertIn('AlienVault OTX', names)

    def test_community_pull_unknown(self):
        """Test /community/pull/<name> 404s for an unknown puller."""
        response = self.client.post(
            '/community/pull/nope', headers=self._get_auth_headers())
        self.assertEqual(response.status_code, 404)

    def test_auth_success(self):
        """Test successful authentication"""
        self.client.post(
            '/subscriptions/my_client',
            json={'password': 'test_password'}
        )
        response = self.client.post('/auth', data={
            'username': 'my_client',
            'password': 'test_password',
        })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['authenticated'])
        self.assertEqual(data['client_id'], 'my_client')

    def test_auth_failure(self):
        """Test failed authentication (wrong password)"""
        self.client.post(
            '/subscriptions/my_client',
            json={'password': 'correct_password'}
        )
        response = self.client.post('/auth', data={
            'username': 'my_client',
            'password': 'wrong_password',
        })
        self.assertEqual(response.status_code, 401)

    def test_list_subscriptions(self):
        """Test list subscriptions endpoint"""
        self.client.post(
            '/subscriptions/ClientA',
            json={'password': 'pass1'}
        )
        response = self.client.get('/subscriptions')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIsInstance(data, list)
        self.assertTrue(any(sub['client_id'] == 'ClientA' for sub in data))

    def test_stix_object_to_dicts(self):
        """Test ThreatIntel object conversion to STIX format"""
        # IP address
        ip_obj = ThreatIntel(
            stix_id="ipv4-addr--123",
            object_type="ipv4-addr",
            labels=["threat", "malicious"],
            confidence=80,
            ip_address="192.168.1.100",
        )
        stix = ip_obj.to_stix_object()
        self.assertEqual(stix['id'], "ipv4-addr--123")
        self.assertEqual(stix['type'], "ipv4-addr")
        self.assertEqual(stix['object']['value'], "192.168.1.100")
        self.assertEqual(stix['labels'], ["threat", "malicious"])

        # File hash
        hash_obj = ThreatIntel(
            stix_id="file-hash--abc123",
            object_type="file-hash",
            labels=["sha256"],
            confidence=75,
            hash_value="a" * 64,
        )
        stix_hash = hash_obj.to_stix_object()
        self.assertEqual(stix_hash['hash_value']['algorithm'], "sha256")
        self.assertEqual(stix_hash['hash_value']['value'], "a" * 64)

    def test_generate_taxii_bundle(self):
        """Test TAXII bundle generation"""
        bundles = [
            {
                "id": "ipv4-addr--123",
                "type": "ipv4-addr",
                "object": {
                    "ipv4-addr": {
                        "value": "192.168.1.100",
                        "host_name": None,
                    }
                },
            },
        ]
        xml = generate_taxii_bundle(bundles)
        self.assertIn('Response', xml)
        self.assertIn('192.168.1.100', xml)
        self.assertIn('v2_1', xml)

    def test_otx_poller_init(self):
        """Test OtxPoller initialization"""
        cfg = {
            'base_url': 'https://otx.alienvault.com/',
            'api_key': 'abc123',
            'poll_interval': 60,
            'max_pulses': 10,
            'object_types': ['ipv4-addr', 'domain-name', 'file-hash'],
        }
        poller = OtxPoller(cfg)
        self.assertEqual(poller.base_url, 'https://otx.alienvault.com')
        self.assertEqual(poller.api_key, 'abc123')
        self.assertEqual(poller.max_pulses, 10)
        self.assertEqual(poller.object_types, ['ipv4-addr', 'domain-name', 'file-hash'])
        self.assertFalse(poller.enabled)
        self.assertFalse(poller._stop)
        self.assertEqual(poller.SOURCE, 'otx')

    def test_otx_poller_urls(self):
        """Test OTX URL construction (pulses listing + indicators)"""
        poller = OtxPoller({'base_url': 'https://otx.example.com/',
                            'max_pulses': 42, 'max_indicators_per_pulse': 7})
        captured = {}

        def fake_get_json(url):
            captured[url] = True
            # return an empty results list for both endpoint shapes
            return {'results': []}

        poller._get_json = fake_get_json
        poller.fetch_recent_pulses()
        poller.fetch_pulse_indicators('PID')

        self.assertEqual(len(captured), 2)
        listing = [u for u in captured if '/otxapi/pulses/?' in u]
        indicators = [u for u in captured if '/otxapi/pulses/PID/indicators/' in u]
        self.assertEqual(len(listing), 1)
        self.assertEqual(len(indicators), 1)
        self.assertIn('sort=-modified', listing[0])
        self.assertIn('limit=42', listing[0])
        self.assertIn('limit=7', indicators[0])
        self.assertTrue(listing[0].startswith('https://otx.example.com/otxapi/pulses/'))

    def test_otx_poller_headers(self):
        """Test OTX request headers (API key optional)"""
        with_key = OtxPoller({'api_key': 'k123'})._headers()
        self.assertEqual(with_key['X-OTX-API-KEY'], 'k123')
        self.assertIn('Accept', with_key)

        without_key = OtxPoller({})._headers()
        self.assertNotIn('X-OTX-API-KEY', without_key)

    def test_otx_indicator_mapping_ipv4(self):
        """Test OTX IPv4 indicator -> STIX descriptor"""
        poller = OtxPoller({'object_types': ['ipv4-addr', 'domain-name', 'file-hash']})
        stix = poller.otx_indicator_to_stix(
            {'indicator': '203.0.113.7', 'type': 'IPv4'}, 'TestPulse', 0)
        self.assertIsNotNone(stix)
        self.assertEqual(stix['type'], 'ipv4-addr')
        self.assertEqual(stix['id'], 'ipv4-addr--203-0-113-7')
        self.assertEqual(stix['object']['ipv4-addr']['value'], '203.0.113.7')
        self.assertIn('otx', stix['labels'])
        self.assertEqual(stix['confidence'], 70)

    def test_otx_indicator_mapping_domain(self):
        """Test OTX domain/hostname indicator -> STIX descriptor"""
        poller = OtxPoller({'object_types': ['ipv4-addr', 'domain-name', 'file-hash']})
        stix = poller.otx_indicator_to_stix(
            {'indicator': 'evil.example.com', 'type': 'domain'}, 'P', 0)
        self.assertIsNotNone(stix)
        self.assertEqual(stix['type'], 'domain-name')
        self.assertEqual(stix['id'], 'domain-name--evil-example-com')

        host = poller.otx_indicator_to_stix(
            {'indicator': 'host.example.com', 'type': 'hostname'}, 'P', 0)
        self.assertEqual(host['type'], 'domain-name')

    def test_otx_indicator_mapping_hash(self):
        """Test OTX file hash indicator -> STIX descriptor with algo"""
        poller = OtxPoller({'object_types': ['ipv4-addr', 'domain-name', 'file-hash']})
        stix = poller.otx_indicator_to_stix(
            {'indicator': 'a' * 64, 'type': 'FileHash-SHA256'}, 'P', 0)
        self.assertIsNotNone(stix)
        self.assertEqual(stix['type'], 'file-hash')
        self.assertEqual(stix['object']['hash_value']['algorithm'], 'sha256')
        self.assertEqual(stix['object']['hash_value']['value'], 'a' * 64)
        self.assertIn('sha256', stix['labels'])

    def test_otx_indicator_mapping_skips_unsupported(self):
        """Test OTX indicator types we do not consume are dropped"""
        poller = OtxPoller({'object_types': ['ipv4-addr', 'domain-name', 'file-hash']})
        for bad in (
            {'indicator': 'http://evil.example/x', 'type': 'URL'},
            {'indicator': 'rule { ... }', 'type': 'YARA'},
            {'indicator': '2001:db8::1', 'type': 'IPV6'},
            {'indicator': 'a@b.com', 'type': 'email'},
        ):
            self.assertIsNone(
                poller.otx_indicator_to_stix(bad, 'P', 0), msg=str(bad))

    def test_otx_indicator_mapping_type_filter(self):
        """Test configured object_types filter excludes unwanted types"""
        poller = OtxPoller({'object_types': ['ipv4-addr']})
        stix = poller.otx_indicator_to_stix(
            {'indicator': 'evil.example.com', 'type': 'domain'}, 'P', 0)
        self.assertIsNone(stix)  # domain-name not in object_types

    def test_merge_does_not_wipe_manual(self):
        """Test merge-mode OTX ingest never removes manual intel"""
        _reset_db()
        ingest_objects([_manual_obj('192.168.1.100')], mode='replace', source='manual')
        ingest_objects([_otx_obj('8.8.8.8')], mode='merge', source='otx')

        response = self.client.get('/objects', headers=self._get_auth_headers())
        self.assertEqual(response.status_code, 200)
        values = {o['value'] for o in response.get_json()['objects']}
        self.assertIn('192.168.1.100', values)  # manual survived
        self.assertIn('8.8.8.8', values)        # OTX added

    def test_replace_scoped_to_manual(self):
        """Test manual replace wipes manual only, not OTX rows"""
        _reset_db()
        ingest_objects([_otx_obj('8.8.8.8')], mode='merge', source='otx')
        # Simulate a web-UI save with a DIFFERENT manual entry.
        ingest_objects([_manual_obj('10.0.0.1')], mode='replace', source='manual')

        response = self.client.get('/objects', headers=self._get_auth_headers())
        values = {o['value'] for o in response.get_json()['objects']}
        self.assertIn('10.0.0.1', values)   # new manual entry
        self.assertIn('8.8.8.8', values)    # OTX row survived the UI save

    def test_merge_is_upsert(self):
        """Test merge mode updates an existing row instead of duplicating"""
        _reset_db()
        ingest_objects([_otx_obj('8.8.8.8')], mode='merge', source='otx')
        ingest_objects([_otx_obj('8.8.8.8')], mode='merge', source='otx')

        response = self.client.get('/objects', headers=self._get_auth_headers())
        values = [o['value'] for o in response.get_json()['objects']]
        self.assertEqual(values.count('8.8.8.8'), 1)  # no duplicate
        self.assertEqual(response.get_json()['count'], 1)

    # ------------------------------------------------------------------
    # Intel gate (filter between server and Vision One)
    # ------------------------------------------------------------------
    def _taxii_values(self):
        """Values actually served to Vision One via the TAXII collection."""
        r = self.client.get(
            '/taxii2/collections/threat-intel/objects/',
            headers=self._get_auth_headers(),
        )
        self.assertEqual(r.status_code, 200)
        envelope = r.get_json()
        content = envelope['content']['content']  # STIX 2.1 bundle
        vals = []
        for o in content['objects']:
            if o.get('type') == 'ipv4-addr':
                vals.append(o['value'])
            elif o.get('type') == 'domain-name':
                vals.append(o['value'])
        return set(vals)

    def test_gate_private_ip_withheld(self):
        """Community private IP is withheld from TAXII but still stored."""
        _reset_db()
        # public community IP (served) + private community IP (withheld)
        ingest_objects([_otx_obj('8.8.8.8')], mode='merge', source='otx')
        ingest_objects([
            {'id': 'ipv4-addr--10-0-0-5', 'type': 'ipv4-addr',
             'object': {'ipv4-addr': {'value': '10.0.0.5'}},
             'labels': ['otx'], 'confidence': 70}
        ], mode='merge', source='otx')

        served = self._taxii_values()
        self.assertIn('8.8.8.8', served)      # public community IP served
        self.assertNotIn('10.0.0.5', served)  # private withheld

        # But it is still stored (web UI / audit still see it).
        stored = self.client.get('/objects', headers=self._get_auth_headers()).get_json()
        stored_vals = {o['value'] for o in stored['objects']}
        self.assertIn('10.0.0.5', stored_vals)

    def test_gate_manual_never_filtered(self):
        """Manual private IP is always served (manual is never gated)."""
        _reset_db()
        ingest_objects([
            {'id': 'ipv4-addr--192-168-1-5', 'type': 'ipv4-addr',
             'object': {'ipv4-addr': {'value': '192.168.1.5'}},
             'labels': ['manual'], 'confidence': 90}
        ], mode='replace', source='manual')

        served = self._taxii_values()
        self.assertIn('192.168.1.5', served)  # manual private IP passes

    def test_gate_private_ip_toggle_off(self):
        """When drop_private_ips is off, community private IP is served."""
        import server
        old = server.FILTER_DROP_PRIVATE_IPS
        server.FILTER_DROP_PRIVATE_IPS = False
        try:
            _reset_db()
            ingest_objects([
                {'id': 'ipv4-addr--172-16-5-9', 'type': 'ipv4-addr',
                 'object': {'ipv4-addr': {'value': '172.16.5.9'}},
                 'labels': ['otx'], 'confidence': 70}
            ], mode='merge', source='otx')
            served = self._taxii_values()
            self.assertIn('172.16.5.9', served)
        finally:
            server.FILTER_DROP_PRIVATE_IPS = old

    def test_gate_stale_withheld(self):
        """Community object older than freshness_days is withheld."""
        import server
        old_days = server.FILTER_FRESHNESS_DAYS
        server.FILTER_FRESHNESS_DAYS = 30
        try:
            _reset_db()
            stale = _otx_obj('8.8.4.4')
            ingest_objects([stale], mode='merge', source='otx')
            # Backdate the stored row's last_seen/modified by 40 days.
            session = server.create_session()
            try:
                row = session.query(server.STIXObject).filter_by(
                    stix_id=stale['id']).one()
                row.last_seen = datetime.utcnow() - timedelta(days=40)
                row.modified = datetime.utcnow() - timedelta(days=40)
                session.commit()
            finally:
                session.close()
            # Rehydrate so the memory store matches the backdated row.
            with server.memory_lock:
                for sid in list(server.memory_store):
                    server.memory_store.pop(sid)
            server.rehydrate_memory()

            served = self._taxii_values()
            self.assertNotIn('8.8.4.4', served)  # stale community IP withheld
        finally:
            server.FILTER_FRESHNESS_DAYS = old_days

    def test_gate_freshness_toggle_off(self):
        """When freshness_days is null, a stale community object is served."""
        import server
        old_days = server.FILTER_FRESHNESS_DAYS
        server.FILTER_FRESHNESS_DAYS = None
        try:
            _reset_db()
            stale = _otx_obj('8.8.4.4')
            ingest_objects([stale], mode='merge', source='otx')
            session = server.create_session()
            try:
                row = session.query(server.STIXObject).filter_by(
                    stix_id=stale['id']).one()
                row.last_seen = datetime.utcnow() - timedelta(days=40)
                row.modified = datetime.utcnow() - timedelta(days=40)
                session.commit()
            finally:
                session.close()
            with server.memory_lock:
                for sid in list(server.memory_store):
                    server.memory_store.pop(sid)
            server.rehydrate_memory()

            served = self._taxii_values()
            self.assertIn('8.8.4.4', served)  # freshness off -> served
        finally:
            server.FILTER_FRESHNESS_DAYS = old_days

    def test_gate_confidence_floor(self):
        """Community object below min_confidence is withheld."""
        import server
        old = server._FILTER_MIN_CONFIDENCE
        server._FILTER_MIN_CONFIDENCE = 80
        try:
            _reset_db()
            # OTX community objects default to confidence 70 < 80.
            ingest_objects([_otx_obj('8.8.4.4')], mode='merge', source='otx')
            served = self._taxii_values()
            self.assertNotIn('8.8.4.4', served)
        finally:
            server._FILTER_MIN_CONFIDENCE = old

    def test_gate_blocklist(self):
        """Community value on the blocklist is withheld."""
        import server
        old = server.FILTER_BLOCKLIST
        server.FILTER_BLOCKLIST = {'blocked.example.com'}
        try:
            _reset_db()
            ingest_objects([
                {'id': 'domain-name--blocked-example-com', 'type': 'domain-name',
                 'object': {'domain-name': {'value': 'blocked.example.com'}},
                 'labels': ['otx'], 'confidence': 70},
            ], mode='merge', source='otx')
            served = self._taxii_values()
            self.assertNotIn('blocked.example.com', served)
        finally:
            server.FILTER_BLOCKLIST = old

    def test_gate_reason_unit(self):
        """community_intel_reason returns the right reason (or None)."""
        import server
        from server import ThreatIntel, community_intel_reason

        # private IP -> 'private-ip' (drop_private_ips default True)
        ip_obj = ThreatIntel(stix_id='ipv4-addr--1-2-3-4', object_type='ipv4-addr',
                             ip_address='10.1.2.3', source='otx')
        self.assertEqual(community_intel_reason(ip_obj, _row()), 'private-ip')

        # public IP, fresh, no blocklist -> None (served)
        pub = ThreatIntel(stix_id='ipv4-addr--8-8-8-8', object_type='ipv4-addr',
                          ip_address='8.8.8.8', source='otx', confidence=70)
        self.assertIsNone(community_intel_reason(pub, _row(last_seen=datetime.utcnow())))

    def test_private_ip_helper(self):
        """_is_private_or_reserved_ip classification sanity."""
        import server
        f = server._is_private_or_reserved_ip
        self.assertTrue(f('10.0.0.1'))
        self.assertTrue(f('192.168.1.1'))
        self.assertTrue(f('172.16.0.1'))
        self.assertTrue(f('127.0.0.1'))
        self.assertTrue(f('169.254.1.1'))
        self.assertTrue(f('0.0.0.0'))
        self.assertTrue(f('255.255.255.255'))
        self.assertFalse(f('8.8.8.8'))
        self.assertFalse(f('1.1.1.1'))
        self.assertFalse(f('not-an-ip'))
        self.assertFalse(f(''))

    def test_vision_one_poller_init(self):
        """Test VisionOnePoller initialization"""
        cfg = {
            'base_url': 'http://localhost:5000',
            'client_id': 'vision_one_client',
            'name': 'Trend Micro Vision One',
            'poll_interval': 60,
            'subscription_name': 'Vision One TAXII Feed',
            'object_types': ['ipv4-addr', 'file-hash', 'domain-name'],
        }
        poller = VisionOnePoller(cfg)
        self.assertEqual(poller.base_url, 'http://localhost:5000')
        self.assertEqual(poller.client_id, 'vision_one_client')
        self.assertEqual(poller.subscription_name, 'Vision One TAXII Feed')
        self.assertEqual(poller.object_types, ['ipv4-addr', 'file-hash', 'domain-name'])
        self.assertFalse(poller._stop)

    def test_vision_one_poller_build_url(self):
        """Test Vision One URL construction"""
        cfg = {
            'base_url': 'http://localhost:5000/',
            'client_id': 'vision_one',
            'poll_interval': 60,
            'subscription_name': 'Vision One TAXII Feed',
        }
        poller = VisionOnePoller(cfg)
        url = poller.base_url
        self.assertEqual(url, 'http://localhost:5000')

    def test_vision_one_poller_auth_headers(self):
        """Test Vision One authentication headers"""
        # Configure auth in server
        app.config['TAXII_AUTH'] = {
            'username': 'vis_user',
            'password': 'vis_pass',
        }
        cfg = {
            'base_url': 'http://localhost:5000',
            'client_id': 'vision_one',
        }
        poller = VisionOnePoller(cfg)
        headers = poller._get_auth_headers()
        self.assertEqual(headers['X-Taxii-Username'], 'vis_user')
        self.assertEqual(headers['X-Taxii-Password'], 'vis_pass')


if __name__ == '__main__':
    unittest.main(verbosity=2)
