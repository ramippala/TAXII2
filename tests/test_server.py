#!/usr/bin/env python3
"""
Tests for TAXII Server Implementation
Tests all TAXII 2 endpoints, ingestion (replace + merge modes), auth,
Vision One integration, and the OTX community-intel puller.
"""

import sys
import os
import io
import tempfile
import types
import unittest
import urllib.parse
from datetime import datetime, timedelta

import jwt

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Tests always run on an isolated SQLite file DB — never pick up DATABASE_URL
# from a local .env (e.g. a dev checkout pointed at PostgreSQL). The .env
# loader only sets vars that are not already in the process environment, so
# setting this before importing server pins the test DB.
os.environ['DATABASE_URL'] = 'sqlite:///' + os.path.join(
    tempfile.gettempdir(), 'taxii2-tests.db')

from server import (
    app,
    ThreatIntel,
    generate_taxii_bundle,
    ingest_objects,
    memory_store,
    init_db,
    OtxPoller,
    VisionOnePoller,
    STIXObject,
    sweep_expired_indicators,
)
import server as _server


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

        # Configure test UI credentials (independent of the live .env).
        self.ui_user = 'test_ui_user'
        self.ui_pass = 'test_ui_pass'
        import server
        server._ui_username = self.ui_user
        server._ui_password = self.ui_pass

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
        # UI creds are set to known test values in setUp (independent of .env).
        response = self.client.post(
            '/ui/login',
            json={'username': self.ui_user, 'password': self.ui_pass},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.set_cookie)  # a session cookie was set
        # The session is now valid.
        session = self.client.get('/ui/session').get_json()
        self.assertTrue(session['authenticated'])
        self.assertEqual(session['user'], self.ui_user)

    def test_ui_login_wrong_password(self):
        """Test /ui/login rejects a wrong password."""
        response = self.client.post(
            '/ui/login',
            json={'username': self.ui_user, 'password': 'wrong-password-xyz'},
        )
        self.assertEqual(response.status_code, 401)

    def test_ui_login_unconfigured_fails_closed(self):
        """With no UI creds configured, /ui/login must reject (503), not
        accept empty==empty credentials."""
        import server
        saved = (server._ui_username, server._ui_password)
        try:
            server._ui_username = ''
            server._ui_password = ''
            response = self.client.post(
                '/ui/login', json={'username': '', 'password': ''},
            )
            self.assertEqual(response.status_code, 503)
            self.assertIn('not configured', response.get_json()['error'])
        finally:
            server._ui_username, server._ui_password = saved

    def test_ui_session_cookie_grants_data_access(self):
        """Test a valid UI session cookie can read /objects (no TAXII headers)."""
        import server
        user, pw = self.ui_user, self.ui_pass
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
        self.client.post('/ui/login', json={'username': self.ui_user, 'password': self.ui_pass})
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
        self.client.post('/ui/login', json={'username': self.ui_user, 'password': self.ui_pass})
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
        # attack-pattern is not a supported store type -> dropped.
        self.assertIsNone(
            server._stix21_object_to_our({'type': 'attack-pattern', 'name': 'x'}))
        self.assertIsNone(server._stix21_object_to_our({'type': 'ipv4-addr', 'value': '999.1.1.1'}))
        self.assertIsNone(server._stix21_object_to_our({'type': 'file'}))

    def test_stix21_object_mapping_extended_types(self):
        """Test the extended SCO / SDO / relationship mapping (graph)."""
        import server
        # url
        d = server._stix21_object_to_our({'type': 'url', 'value': 'http://evil.example.com/x'})
        self.assertIsNotNone(d)
        self.assertEqual(d['type'], 'url')
        self.assertEqual(d['object']['url']['value'], 'http://evil.example.com/x')
        # email-addr
        d = server._stix21_object_to_our({'type': 'email-addr', 'value': 'a@evil.example.com'})
        self.assertEqual(d['type'], 'email-addr')
        # invalid email -> dropped
        self.assertIsNone(server._stix21_object_to_our({'type': 'email-addr', 'value': 'not-an-email'}))
        # malware SDO (previously unsupported)
        d = server._stix21_object_to_our({'type': 'malware', 'name': 'trickbot'})
        self.assertEqual(d['type'], 'malware')
        self.assertEqual(d['object']['malware']['name'], 'trickbot')
        # relationship (graph edge preserved)
        d = server._stix21_object_to_our({
            'type': 'relationship',
            'source_ref': 'malware--a',
            'relationship_type': 'uses',
            'target_ref': 'tool--b',
        })
        self.assertEqual(d['type'], 'relationship')
        self.assertEqual(d['object']['relationship']['relationship_type'], 'uses')
        # incomplete relationship -> dropped
        self.assertIsNone(server._stix21_object_to_our({
            'type': 'relationship', 'source_ref': 'malware--a'}))

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
            {'type': 'attack-pattern', 'name': 'drop'},   # unsupported -> skipped
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


class TestRevocationAndTTL(unittest.TestCase):
    """Manual revocation, TTL auto-revocation, and TAXII 2.1 match filters."""

    def setUp(self):
        self.client = app.test_client()
        _reset_db()
        app.config['TAXII_AUTH'] = {
            'username': 'test_taxii_user',
            'password': 'test_taxii_pass',
        }
        self.auth = {
            'X-Taxii-Username': 'test_taxii_user',
            'X-Taxii-Password': 'test_taxii_pass',
        }

    def _ingest(self, objs):
        return self.client.post(
            '/feed/ingest', json={'stix_objects': objs}, headers=self.auth
        )

    def _bundle(self, qs=''):
        r = self.client.get(
            '/taxii2/collections/threat-intel/objects/' + qs,
            headers=self.auth,
        )
        self.assertEqual(r.status_code, 200)
        return r.get_json()['content']['content']['objects']

    def test_revoke_object(self):
        self.assertEqual(self._ingest([_manual_obj('1.2.3.4')]).status_code, 200)
        # default action = revoke
        r = self.client.post(
            '/objects/ipv4-addr--1-2-3-4/revoke', json={}, headers=self.auth
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()['revoked'])
        # served in the TAXII bundle with revoked: true
        objs = self._bundle()
        self.assertEqual(len(objs), 1)
        self.assertTrue(objs[0]['revoked'])

    def test_unrevoke_object(self):
        self._ingest([_manual_obj('5.6.7.8')])
        self.client.post(
            '/objects/ipv4-addr--5-6-7-8/revoke', json={'action': 'revoke'},
            headers=self.auth,
        )
        r = self.client.post(
            '/objects/ipv4-addr--5-6-7-8/revoke', json={'action': 'unrevoke'},
            headers=self.auth,
        )
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.get_json()['revoked'])
        objs = self._bundle()
        self.assertFalse(objs[0]['revoked'])

    def test_revoke_no_auth(self):
        self._ingest([_manual_obj('9.8.7.6')])
        r = self.client.post('/objects/ipv4-addr--9-8-7-6/revoke', json={})
        self.assertEqual(r.status_code, 401)

    def test_revoke_unknown_object(self):
        r = self.client.post(
            '/objects/ipv4-addr--0-0-0-0/revoke', json={}, headers=self.auth
        )
        self.assertEqual(r.status_code, 404)

    def test_revoke_bad_action(self):
        self._ingest([_manual_obj('4.3.2.1')])
        r = self.client.post(
            '/objects/ipv4-addr--4-3-2-1/revoke', json={'action': 'nope'},
            headers=self.auth,
        )
        self.assertEqual(r.status_code, 400)

    def test_revoke_sticky_across_replace_ingest(self):
        """A UI save (replace) must not silently reinstate a revoked object."""
        self._ingest([_manual_obj('2.2.2.2')])
        self.client.post(
            '/objects/ipv4-addr--2-2-2-2/revoke', json={'action': 'revoke'},
            headers=self.auth,
        )
        # save again WITHOUT a revoked flag -> stays revoked
        self._ingest([_manual_obj('2.2.2.2')])
        objs = self._bundle()
        self.assertEqual(len(objs), 1)
        self.assertTrue(objs[0]['revoked'])

    def test_objects_endpoint_reports_revoked(self):
        self._ingest([_manual_obj('3.3.3.3')])
        self.client.post(
            '/objects/ipv4-addr--3-3-3-3/revoke', json={}, headers=self.auth
        )
        r = self.client.get('/objects', headers=self.auth)
        o = r.get_json()['objects'][0]
        self.assertTrue(o['revoked'])
        self.assertIsNotNone(o['revoked_at'])

    def test_ttl_sweep_auto_revokes_expired(self):
        """An IP older than ipv4_days is auto-revoked (served revoked:true)."""
        old = datetime.utcnow() - timedelta(days=30)  # > default 14d
        self._ingest([_manual_obj('6.6.6.6')])
        # backdate the row past its TTL
        session = _server.create_session()
        try:
            row = session.query(STIXObject).filter_by(
                stix_id='ipv4-addr--6-6-6-6').first()
            row.last_seen = old
            row.first_seen = old
            session.commit()
        finally:
            session.close()
        newly = sweep_expired_indicators()
        self.assertEqual(newly, 1)
        objs = self._bundle()
        self.assertEqual(len(objs), 1)
        self.assertTrue(objs[0]['revoked'])

    def test_ttl_sweep_keeps_fresh_objects(self):
        self._ingest([_manual_obj('8.8.8.8')])  # fresh -> untouched
        self.assertEqual(sweep_expired_indicators(), 0)
        objs = self._bundle()
        self.assertFalse(objs[0]['revoked'])

    def test_match_type_filter(self):
        self._ingest([
            _manual_obj('1.1.1.1'),
            {'id': 'domain-name--a-b-c', 'type': 'domain-name',
             'object': {'domain-name': {'value': 'a.b.c'}}, 'labels': [], 'confidence': 50},
        ])
        objs = self._bundle('?match%5Btype%5D=domain-name')  # match[type]=domain-name
        self.assertEqual(len(objs), 1)
        self.assertEqual(objs[0]['type'], 'domain-name')
        objs = self._bundle('?match%5Btype%5D=ipv4-addr')
        self.assertEqual(len(objs), 1)
        self.assertEqual(objs[0]['type'], 'ipv4-addr')

    def test_match_id_filter(self):
        self._ingest([
            _manual_obj('1.1.1.1'),
            _manual_obj('2.2.2.2'),
        ])
        objs = self._bundle('?match%5Bid%5D=ipv4-addr--1-1-1-1')
        self.assertEqual(len(objs), 1)
        self.assertEqual(objs[0]['id'], 'ipv4-addr--1-1-1-1')

    def test_added_after_param(self):
        self._ingest([_manual_obj('7.7.7.7')])
        future = (datetime.utcnow() + timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        objs = self._bundle('?added_after=' + future)
        self.assertEqual(len(objs), 0)  # nothing modified after "now+1d"


class TestCsvImport(unittest.TestCase):
    """GT-team CSV upload with fuzzy header mapping."""

    def setUp(self):
        self.client = app.test_client()
        _reset_db()
        app.config['TAXII_AUTH'] = {
            'username': 'test_taxii_user',
            'password': 'test_taxii_pass',
        }
        self.auth = {
            'X-Taxii-Username': 'test_taxii_user',
            'X-Taxii-Password': 'test_taxii_pass',
        }

    def _post_csv(self, text):
        return self.client.post(
            '/feed/import-csv', data={'file': (io.BytesIO(text.encode('utf-8')), 'intel.csv')},
            headers=self.auth,
        )

    def test_fuzzy_headers(self):
        """IP_Address / Destination / malicious_domain / sha256 all map.

        Rows carrying both an IP and a domain yield ONE object per value.
        """
        csv_text = (
            "IP_Address,Destination,malicious_domain,sha256,labels,confidence\n"
            "1.2.3.4,,evil.example.com,,c2,90\n"
            ",5.6.7.8,bot.evil.net,,apt,80\n"
            ",,,abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789,mw,70\n"
            "999.1.1.1,,,,,99\n"  # invalid IP -> skipped
        )
        r = self._post_csv(csv_text)
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body['imported'], 5)  # 2+2+1 objects; row 4 skipped
        self.assertEqual(body['skipped_total'], 1)
        # verify stored types
        r = self.client.get('/objects', headers=self.auth)
        by_type = {}
        for o in r.get_json()['objects']:
            by_type.setdefault(o['type'], []).append(o['value'])
        self.assertEqual(by_type['ipv4-addr'], ['1.2.3.4', '5.6.7.8'])
        self.assertEqual(by_type['domain-name'], ['evil.example.com', 'bot.evil.net'])
        self.assertEqual(by_type['file-hash'],
                         ['abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'])

    def test_import_merges_not_replaces(self):
        """CSV import (merge) must not wipe existing manual rows."""
        self.client.post('/feed/ingest', json={'stix_objects': [_manual_obj('9.9.9.9')]},
                         headers=self.auth)
        r = self._post_csv("ip\n1.1.1.1\n")
        self.assertEqual(r.status_code, 200)
        r = self.client.get('/objects', headers=self.auth)
        values = {o['value'] for o in r.get_json()['objects']}
        self.assertEqual(values, {'9.9.9.9', '1.1.1.1'})

    def test_import_no_auth(self):
        r = self.client.post('/feed/import-csv', data={'file': (io.BytesIO(b'ip\n1.1.1.1'), 'a.csv')})
        self.assertEqual(r.status_code, 401)

    def test_import_empty_csv(self):
        r = self._post_csv("")
        self.assertEqual(r.status_code, 400)

    def test_import_no_recognizable_rows(self):
        r = self._post_csv("foo,bar\nhello,world\n")
        self.assertEqual(r.status_code, 400)
        self.assertIn('no recognizable rows', r.get_json()['error'])


class TestSso(unittest.TestCase):
    """Microsoft Entra ID OIDC SSO: PKCE redirect, state/nonce, JWT
    validation (real RS256 with a local key), allow-lists, cookie issue.

    Only the network calls (code exchange) are mocked; token signature
    verification runs for real against a locally generated RSA key.
    """

    _SSO_KEYS = ('SSO_ENABLED', 'SSO_TENANT', 'SSO_CLIENT_ID', 'SSO_CLIENT_SECRET',
                 'SSO_REDIRECT_URI', 'SSO_AUTH_ENDPOINT', 'SSO_ISSUER',
                 'SSO_ALLOW_DOMAINS', 'SSO_ALLOW_UPNS', 'SSO_ALLOW_GROUPS',
                 '_sso_jwks_client')

    def setUp(self):
        self.client = app.test_client()
        _reset_db()
        app.config['TAXII_AUTH'] = {
            'username': 'test_taxii_user', 'password': 'test_taxii_pass',
        }
        self._saved = {k: getattr(_server, k) for k in self._SSO_KEYS}
        _server.SSO_ENABLED = True
        _server.SSO_TENANT = 'test-tenant'
        _server.SSO_CLIENT_ID = 'test-client-id'
        _server.SSO_CLIENT_SECRET = 'test-secret'
        _server.SSO_REDIRECT_URI = 'http://localhost:5000/ui/sso/callback'
        _server.SSO_AUTH_ENDPOINT = (
            'https://login.microsoftonline.com/test-tenant/oauth2/v2.0/authorize')
        _server.SSO_ISSUER = ''
        _server.SSO_ALLOW_DOMAINS = ()
        _server.SSO_ALLOW_UPNS = set()
        _server.SSO_ALLOW_GROUPS = set()

        from cryptography.hazmat.primitives.asymmetric import rsa
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._priv = priv
        self._pub = priv.public_key()
        _server._sso_jwks_client = _FakeJwkClient(self._pub)

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(_server, k, v)

    def _id_token(self, **claims):
        base = {
            'iss': 'https://login.microsoftonline.com/test-tenant/v2.0',
            'aud': 'test-client-id',
            'exp': datetime.utcnow() + timedelta(minutes=5),
            'iat': datetime.utcnow(),
            'sub': 'user-sub-123',
            'nonce': 'nonce-abc',
            'preferred_username': 'jdoe@contoso.com',
        }
        base.update(claims)
        return jwt.encode(base, self._priv, algorithm='RS256')

    def _set_oauth_cookie(self, state, nonce, code_verifier):
        token = _server._sso_oauth_state_token(
            {'state': state, 'nonce': nonce, 'code_verifier': code_verifier})
        # The Flask test client drops a manual Cookie header; set_cookie()
        # is the supported way to send cookies.
        self.client.set_cookie('taxii2_ui_sso', token, domain='localhost')

    def test_sso_disabled_404(self):
        _server.SSO_ENABLED = False
        self.assertEqual(self.client.get('/ui/sso').status_code, 404)
        self.assertEqual(self.client.get('/ui/sso/callback').status_code, 404)

    def test_session_reports_sso(self):
        body = self.client.get('/ui/session').get_json()
        self.assertIn('sso', body)
        self.assertTrue(body['sso']['enabled'])

    def test_sso_start_redirects_with_pkce(self):
        r = self.client.get('/ui/sso')
        self.assertEqual(r.status_code, 302)
        loc = r.headers['Location']
        self.assertTrue(loc.startswith(_server.SSO_AUTH_ENDPOINT))
        for frag in ('client_id=test-client-id', 'response_type=code',
                     'code_challenge_method=S256', 'response_mode=query'):
            self.assertIn(frag, loc)
        # oauth state cookie present
        set_cookies = [h for h in r.headers.getlist('Set-Cookie')
                       if h.startswith('taxii2_ui_sso=')]
        self.assertEqual(len(set_cookies), 1)
        raw = set_cookies[0].split(';', 1)[0].split('=', 1)[1]
        oauth = _server._oauth_state_serializer.loads(raw, max_age=600)
        self.assertIn('state', loc)
        # PKCE: challenge must equal S256(verifier)
        import base64, hashlib
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(oauth['code_verifier'].encode()).digest()
        ).rstrip(b'=').decode()
        self.assertIn('code_challenge=' + urllib.parse.quote(expected), loc)

    def test_callback_rejects_state_mismatch(self):
        self._set_oauth_cookie('state-A', 'nonce-abc', 'verifier-1')
        r = self.client.get('/ui/sso/callback?code=abc&state=state-B')
        self.assertEqual(r.status_code, 401)
        self.assertIn('state mismatch', r.get_data(as_text=True))

    def test_callback_rejects_missing_state_cookie(self):
        r = self.client.get('/ui/sso/callback?code=abc&state=state-A')
        self.assertEqual(r.status_code, 401)

    def test_callback_happy_path_sets_session(self):
        import unittest.mock
        tok = self._id_token()
        with unittest.mock.patch.object(
                _server, '_sso_exchange_code',
                return_value={'id_token': tok}) as exch:
            self._set_oauth_cookie('state-X', 'nonce-abc', 'verifier-X')
            r = self.client.get(
                '/ui/sso/callback?code=authcode123&state=state-X',
            )
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers['Location'], '/')
        exch.assert_called_once_with('authcode123', 'verifier-X')
        set_cookies = [h for h in r.headers.getlist('Set-Cookie')]
        sess = [h for h in set_cookies if h.startswith('taxii2_ui_session=')]
        self.assertEqual(len(sess), 1)
        payload = _server._session_serializer.loads(
            sess[0].split(';', 1)[0].split('=', 1)[1])
        self.assertEqual(payload['user'], 'jdoe@contoso.com')

    def test_callback_rejects_bad_signature_audience(self):
        import unittest.mock
        tok = self._id_token(aud='some-other-app')  # wrong audience
        with unittest.mock.patch.object(
                _server, '_sso_exchange_code',
                return_value={'id_token': tok}):
            self._set_oauth_cookie('s1', 'nonce-abc', 'v')
            r = self.client.get(
                '/ui/sso/callback?code=c&state=s1',
            )
        self.assertEqual(r.status_code, 401)
        self.assertIn('token validation failed', r.get_data(as_text=True))

    def test_callback_rejects_nonce_mismatch(self):
        import unittest.mock
        tok = self._id_token(nonce='different-nonce')
        with unittest.mock.patch.object(
                _server, '_sso_exchange_code',
                return_value={'id_token': tok}):
            self._set_oauth_cookie('s2', 'nonce-abc', 'v')
            r = self.client.get(
                '/ui/sso/callback?code=c&state=s2',
            )
        self.assertEqual(r.status_code, 401)
        self.assertIn('token validation failed', r.get_data(as_text=True))

    def test_allowlist_domain(self):
        _server.SSO_ALLOW_DOMAINS = ('contoso.com',)
        ok, _ = _server._sso_user_allowed({'preferred_username': 'jdoe@contoso.com'})
        self.assertTrue(ok)
        ok, reason = _server._sso_user_allowed({'preferred_username': 'eve@evil.com'})
        self.assertFalse(ok)
        self.assertEqual(reason, 'domain not allowed')

    def test_allowlist_upn(self):
        _server.SSO_ALLOW_UPNS = {'jdoe@contoso.com'}
        ok, _ = _server._sso_user_allowed({'preferred_username': 'jdoe@contoso.com'})
        self.assertTrue(ok)
        ok, _ = _server._sso_user_allowed({'preferred_username': 'other@contoso.com'})
        self.assertFalse(ok)

    def test_allowlist_groups(self):
        _server.SSO_ALLOW_GROUPS = {'group-object-1'}
        ok, _ = _server._sso_user_allowed(
            {'preferred_username': 'jdoe@contoso.com',
             'groups': ['group-object-1', 'other']})
        self.assertTrue(ok)
        ok, reason = _server._sso_user_allowed(
            {'preferred_username': 'jdoe@contoso.com', 'groups': ['other']})
        self.assertFalse(ok)
        self.assertEqual(reason, 'not in an allowed Entra group')

    def test_allowlist_callback_denial(self):
        import unittest.mock
        _server.SSO_ALLOW_UPNS = {'onlythis@contoso.com'}
        tok = self._id_token(preferred_username='jdoe@contoso.com')
        with unittest.mock.patch.object(
                _server, '_sso_exchange_code',
                return_value={'id_token': tok}):
            self._set_oauth_cookie('s3', 'nonce-abc', 'v')
            r = self.client.get(
                '/ui/sso/callback?code=c&state=s3',
            )
        self.assertEqual(r.status_code, 401)
        self.assertIn('not authorized', r.get_data(as_text=True))


class TestDotenv(unittest.TestCase):
    """Minimal .env loader: parsing, precedence, missing file, path override."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, 'test.env')
        # Keys the tests touch, saved/restored so nothing leaks between tests.
        self._keys = ('TEST_DOTENV_A', 'TEST_DOTENV_B', 'TEST_DOTENV_C',
                      'TAXII_ENV_FILE', 'TEST_DOTENV_OVERRIDE')
        self._saved = {k: os.environ.pop(k, None) for k in self._keys}

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def _write(self, text):
        with open(self.path, 'w', encoding='utf-8') as fh:
            fh.write(text)

    def _load(self):
        _server._load_dotenv(_server.Path(self.path))

    def test_parses_values_comments_and_quotes(self):
        self._write(
            '# a comment line\n'
            '\n'
            'TEST_DOTENV_A=plain\n'
            'TEST_DOTENV_B="double quoted"\n'
            "TEST_DOTENV_C='single quoted'\n"
            '   # indented comment\n'
        )
        self._load()
        self.assertEqual(os.environ['TEST_DOTENV_A'], 'plain')
        self.assertEqual(os.environ['TEST_DOTENV_B'], 'double quoted')
        self.assertEqual(os.environ['TEST_DOTENV_C'], 'single quoted')

    def test_process_env_always_wins(self):
        self._write('TEST_DOTENV_A=from-file\n')
        os.environ['TEST_DOTENV_A'] = 'from-env'
        self._load()
        self.assertEqual(os.environ['TEST_DOTENV_A'], 'from-env')

    def test_missing_file_is_noop(self):
        # Should not raise, and should not set anything.
        _server._load_dotenv(_server.Path(self.tmp.name) / 'does-not-exist.env')
        self.assertNotIn('TEST_DOTENV_A', os.environ)

    def test_dotenv_path_default_and_override(self):
        # Default: .env next to server.py (repo root), unless TAXII_ENV_FILE.
        self._write('TEST_DOTENV_A=x\n')
        os.environ['TAXII_ENV_FILE'] = self.path
        try:
            self.assertEqual(str(_server._dotenv_path()), self.path)
        finally:
            del os.environ['TAXII_ENV_FILE']
        default = str(_server._dotenv_path())
        # Default .env lives next to server.py, whatever the repo dir is named.
        self.assertEqual(
            default,
            os.path.join(os.path.dirname(os.path.abspath(_server.__file__)), '.env'),
        )
        self.assertFalse(default.startswith(self.tmp.name))


class TestSaveAndDelete(unittest.TestCase):
    """Web-UI save semantics (mode=merge) + POST /feed/delete (purge option)."""

    def setUp(self):
        self.client = app.test_client()
        _reset_db()
        app.config['TAXII_AUTH'] = {
            'username': 'test_taxii_user', 'password': 'test_taxii_pass',
        }
        self.auth = {
            'X-Taxii-Username': 'test_taxii_user',
            'X-Taxii-Password': 'test_taxii_pass',
        }

    def _seed(self):
        # 10 manual IPs + 1 OTX IP (community source, must survive saves).
        manual = [_manual_obj(f"203.0.113.{i}") for i in range(1, 11)]
        self._ingest(manual)
        # Simulate the puller's write path (tags source='otx', merge mode).
        ingest_objects([_otx_obj("8.8.8.8")], mode='merge', source='otx')

    def _ingest(self, stix_objects, mode=None):
        payload = {'stix_objects': stix_objects}
        if mode:
            payload['mode'] = mode
        return self.client.post('/feed/ingest', json=payload, headers=self.auth)

    def _ids(self):
        r = self.client.get('/objects', headers=self.auth)
        self.assertEqual(r.status_code, 200)
        return {o['id']: o for o in r.get_json()['objects']}

    def test_ingest_mode_merge_preserves_everything(self):
        self._seed()
        ids = self._ids()
        self.assertEqual(len(ids), 11)
        self.assertEqual(ids['ipv4-addr--8-8-8-8']['source'], 'otx')

        # UI save: merge with 5 (edited) manual rows + 1 brand-new row.
        save = [_manual_obj(f"203.0.113.{i}") for i in range(1, 6)]
        save.append(_manual_obj("203.0.113.99"))  # new
        r = self._ingest(save, mode='merge')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['mode'], 'merge')

        ids = self._ids()
        # The 5 other manual rows + the OTX row survived (not wiped).
        for i in range(6, 11):
            self.assertIn(f"ipv4-addr--203-0-113-{i}", ids)
        self.assertIn('ipv4-addr--8-8-8-8', ids)
        self.assertEqual(ids['ipv4-addr--8-8-8-8']['source'], 'otx')
        # New row merged in; total = 10 manual + 1 new + 1 otx.
        self.assertIn('ipv4-addr--203-0-113-99', ids)
        self.assertEqual(len(ids), 12)

    def test_ingest_default_is_replace(self):
        self._seed()
        self._ingest([_manual_obj("203.0.113.1")])  # legacy replace
        ids = self._ids()
        # Other manual rows wiped; otx row survives.
        self.assertNotIn('ipv4-addr--203-0-113-2', ids)
        self.assertIn('ipv4-addr--203-0-113-1', ids)
        self.assertIn('ipv4-addr--8-8-8-8', ids)

    def test_ingest_bad_mode_400(self):
        r = self._ingest([_manual_obj()], mode='bogus')
        self.assertEqual(r.status_code, 400)

    def test_delete_ids(self):
        self._seed()
        r = self.client.post('/feed/delete',
                             json={'ids': ['ipv4-addr--203-0-113-1', 'ipv4-addr--8-8-8-8']},
                             headers=self.auth)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['deleted'], 2)
        ids = self._ids()
        self.assertNotIn('ipv4-addr--203-0-113-1', ids)
        self.assertNotIn('ipv4-addr--8-8-8-8', ids)  # any-source delete
        self.assertIn('ipv4-addr--203-0-113-2', ids)

    def test_delete_empty_ids_400(self):
        r = self.client.post('/feed/delete', json={'ids': []}, headers=self.auth)
        self.assertEqual(r.status_code, 400)
        r = self.client.post('/feed/delete', json={}, headers=self.auth)
        self.assertEqual(r.status_code, 400)

    def test_delete_unauth_401(self):
        r = self.client.post('/feed/delete', json={'ids': ['x']})
        self.assertEqual(r.status_code, 401)


class TestExtendedTypesAndValidation(unittest.TestCase):
    """New STIX object types (url / email-addr / ipv6-addr / mac-addr /
    windows-registry-key / autonomous-system), the STIX graph objects
    (relationship / malware / threat-actor / campaign) and ingest validation.
    """

    def setUp(self):
        self.client = app.test_client()
        _reset_db()
        app.config['TAXII_AUTH'] = {
            'username': 'test_taxii_user',
            'password': 'test_taxii_pass',
        }
        self.auth = {
            'X-Taxii-Username': 'test_taxii_user',
            'X-Taxii-Password': 'test_taxii_pass',
        }

    def _ingest(self, objs):
        return self.client.post(
            '/feed/ingest', json={'stix_objects': objs}, headers=self.auth)

    def _bundle(self, qs=''):
        r = self.client.get(
            '/taxii2/collections/threat-intel/objects/' + qs,
            headers=self.auth,
        )
        self.assertEqual(r.status_code, 200)
        return r.get_json()['content']['content']['objects']

    def test_ingest_and_serve_url_email_ipv6(self):
        r = self._ingest([
            {'id': 'url--evil-x', 'type': 'url',
             'object': {'url': {'value': 'http://evil.example.com/x'}},
             'labels': ['malicious'], 'confidence': 80},
            {'id': 'email-addr--a-b', 'type': 'email-addr',
             'object': {'email-addr': {'value': 'a@evil.example.com'}},
             'labels': ['malicious'], 'confidence': 60},
            {'id': 'ipv6-addr--2001-0db8--1', 'type': 'ipv6-addr',
             'object': {'ipv6-addr': {'value': '2001:db8::1'}},
             'labels': ['malicious'], 'confidence': 70},
        ])
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['objects_count'], 3)

        objs = self._bundle()
        by_type = {o['type']: o for o in objs}
        self.assertEqual(by_type['url']['value'], 'http://evil.example.com/x')
        self.assertEqual(by_type['email-addr']['value'], 'a@evil.example.com')
        self.assertEqual(by_type['ipv6-addr']['value'], '2001:db8::1')

        # /objects lists them with their value
        r = self.client.get('/objects', headers=self.auth)
        by_type = {o['type']: o for o in r.get_json()['objects']}
        self.assertEqual(by_type['url']['value'], 'http://evil.example.com/x')

    def test_windows_registry_key_and_asn(self):
        r = self._ingest([
            {'id': 'windows-registry-key--hkcu', 'type': 'windows-registry-key',
             'object': {'windows-registry-key': {'key': 'HKEY_CURRENT_USER\\Software\\Evil'}},
             'labels': ['registry'], 'confidence': 55},
            {'id': 'autonomous-system--12345', 'type': 'autonomous-system',
             'object': {'autonomous-system': {'number': 64512}},
             'labels': ['asn'], 'confidence': 50},
        ])
        self.assertEqual(r.status_code, 200)
        objs = self._bundle()
        by_type = {o['type']: o for o in objs}
        self.assertEqual(by_type['windows-registry-key']['key'],
                         'HKEY_CURRENT_USER\\Software\\Evil')
        self.assertEqual(by_type['autonomous-system']['number'], 64512)

    def test_indicator_over_url_renders_url_pattern(self):
        self._ingest([
            {'id': 'indicator--cafe', 'type': 'indicator',
             'object': {'indicator': {'value': 'http://evil.example.com/x'}},
             'labels': ['url'], 'confidence': 90},
        ])
        objs = self._bundle()
        self.assertEqual(len(objs), 1)
        o = objs[0]
        self.assertEqual(o['type'], 'indicator')
        self.assertEqual(o['pattern'], "[url:value = 'http://evil.example.com/x']")

    def test_guess_object_type_extended(self):
        import server
        cases = {
            'http://a.example.com/x': ('url', 'url'),
            'https://a.example.com/x?q=1': ('url', 'url'),
            'a@evil.example.com': ('email-addr', 'email-addr'),
            '2001:db8::1': ('ipv6-addr', 'ipv6-addr'),
            'aa:bb:cc:dd:ee:ff': ('mac-addr', 'mac-addr'),
            'AS12345': ('autonomous-system', 'autonomous-system'),
            '1.2.3.4': ('ipv4-addr', 'ipv4-addr'),
            'evil.example.com': ('domain-name', 'domain-name'),
            'free text': ('indicator', 'indicator'),
        }
        for value, (otype, algo_marker) in cases.items():
            guessed, _ = server._guess_object_type(value)
            self.assertEqual(guessed, otype, f'value {value!r}')

    def test_validation_rejects_bad_id_prefix(self):
        # type url but id says ipv4-addr -> skipped, not stored
        r = self._ingest([
            {'id': 'ipv4-addr--oops', 'type': 'url',
             'object': {'url': {'value': 'http://evil.example.com/x'}},
             'labels': ['x'], 'confidence': 50},
        ])
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['objects_count'], 0)
        self.assertEqual(self.client.get('/objects', headers=self.auth).get_json()['count'], 0)

    def test_validation_rejects_unsupported_type_and_bad_confidence(self):
        r = self._ingest([
            {'id': 'banana--1', 'type': 'banana',
             'object': {'banana': {'value': 'x'}}, 'labels': [], 'confidence': 50},
            {'id': 'ipv4-addr--1-2-3-4', 'type': 'ipv4-addr',
             'object': {'ipv4-addr': {'value': '1.2.3.4'}},
             'labels': ['x'], 'confidence': 999},
            {'id': 'ipv4-addr--5-6-7-8', 'type': 'ipv4-addr',
             'object': {'ipv4-addr': {'value': '5.6.7.8'}},
             'labels': ['x'], 'confidence': 50, 'modified': 'not-a-date'},
        ])
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['objects_count'], 0)

    def test_validation_skips_only_bad_rows(self):
        r = self._ingest([
            {'id': 'banana--1', 'type': 'banana',
             'object': {'banana': {'value': 'x'}}, 'labels': [], 'confidence': 50},
            {'id': 'ipv4-addr--9-9-9-9', 'type': 'ipv4-addr',
             'object': {'ipv4-addr': {'value': '9.9.9.9'}},
             'labels': ['x'], 'confidence': 50},
        ])
        self.assertEqual(r.get_json()['objects_count'], 1)
        objs = self.client.get('/objects', headers=self.auth).get_json()['objects']
        self.assertEqual([o['value'] for o in objs], ['9.9.9.9'])

    def test_graph_relationship_ingest_and_serve(self):
        r = self._ingest([
            {'id': 'malware--trickbot', 'type': 'malware',
             'object': {'malware': {'name': 'TrickBot'}},
             'labels': ['malware'], 'confidence': 70},
            {'id': 'threat-actor--apt41', 'type': 'threat-actor',
             'object': {'threat-actor': {'name': 'APT41'}},
             'labels': ['apt'], 'confidence': 70},
            {'id': 'relationship--r1', 'type': 'relationship',
             'object': {'relationship': {
                 'relationship_type': 'uses',
                 'source_ref': 'malware--trickbot',
                 'target_ref': 'threat-actor--apt41'}},
             'labels': ['graph'], 'confidence': 70},
        ])
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['objects_count'], 3)

        objs = self._bundle()
        by_type = {o['type']: o for o in objs}
        self.assertEqual(by_type['malware']['name'], 'TrickBot')
        self.assertTrue(by_type['malware']['is_family'])
        self.assertEqual(by_type['threat-actor']['name'], 'APT41')
        self.assertEqual(by_type['threat-actor']['threat_actor_types'], ['unknown'])
        rel = by_type['relationship']
        self.assertEqual(rel['relationship_type'], 'uses')
        self.assertEqual(rel['source_ref'], 'malware--trickbot')
        self.assertEqual(rel['target_ref'], 'threat-actor--apt41')

        # /objects shows the edge as a readable summary
        r = self.client.get('/objects', headers=self.auth)
        rel_row = next(o for o in r.get_json()['objects'] if o['type'] == 'relationship')
        self.assertIn('malware--trickbot → uses → threat-actor--apt41', rel_row['value'])

    def test_incomplete_relationship_rejected(self):
        r = self._ingest([
            {'id': 'relationship--r1', 'type': 'relationship',
             'object': {'relationship': {'source_ref': 'malware--a'}},
             'labels': [], 'confidence': 50},
        ])
        self.assertEqual(r.get_json()['objects_count'], 0)

    def test_campaign_ingest(self):
        r = self._ingest([
            {'id': 'campaign--c1', 'type': 'campaign',
             'object': {'campaign': {'name': 'Operation Beep'}},
             'labels': ['campaign'], 'confidence': 60},
        ])
        objs = self._bundle()
        self.assertEqual(objs[0]['type'], 'campaign')
        self.assertEqual(objs[0]['name'], 'Operation Beep')


class TestTaxiiPagination(unittest.TestCase):
    """TAXII 2.1 Get Objects pagination: limit / next / more (keyset)."""

    def setUp(self):
        self.client = app.test_client()
        _reset_db()
        app.config['TAXII_AUTH'] = {
            'username': 'test_taxii_user',
            'password': 'test_taxii_pass',
        }
        self.auth = {
            'X-Taxii-Username': 'test_taxii_user',
            'X-Taxii-Password': 'test_taxii_pass',
        }

    def _ingest_n(self, n):
        objs = [{
            'id': f'ipv4-addr--1-1-1-{i}',
            'type': 'ipv4-addr',
            'object': {'ipv4-addr': {'value': f'1.1.1.{i}'}},
            'labels': ['t'], 'confidence': 50,
        } for i in range(1, n + 1)]
        r = self.client.post('/feed/ingest', json={'stix_objects': objs},
                             headers=self.auth)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['objects_count'], n)

    def _page(self, qs):
        r = self.client.get(
            '/taxii2/collections/threat-intel/objects/' + qs,
            headers=self.auth)
        self.assertEqual(r.status_code, 200)
        return r.get_json()

    def test_pages_walk_without_duplicates_or_loss(self):
        self._ingest_n(7)
        ids = []
        more = True
        nxt = None
        pages = 0
        while more:
            qs = '?limit=3'
            if nxt:
                qs += '&next=' + urllib.parse.quote(nxt)
            msg = self._page(qs)
            objs = msg['content']['content']['objects']
            self.assertLessEqual(len(objs), 3)
            ids.extend(o['id'] for o in objs)
            more = msg['more']
            nxt = msg.get('next')
            pages += 1
            self.assertLess(pages, 10)  # guard against infinite loops
        self.assertEqual(pages, 3)
        self.assertEqual(sorted(ids), sorted(
            f'ipv4-addr--1-1-1-{i}' for i in range(1, 8)))
        self.assertEqual(len(set(ids)), 7)

    def test_single_page_when_fewer_than_limit(self):
        self._ingest_n(2)
        msg = self._page('?limit=5')
        self.assertFalse(msg['more'])
        self.assertNotIn('next', msg)
        self.assertEqual(len(msg['content']['content']['objects']), 2)

    def test_more_flag_off_without_limit(self):
        self._ingest_n(4)
        msg = self._page('')
        self.assertFalse(msg['more'])
        self.assertNotIn('next', msg)
        self.assertEqual(len(msg['content']['content']['objects']), 4)

    def test_limit_zero_and_non_numeric_400(self):
        self._ingest_n(3)
        for bad in ('0', '-1', 'abc', '1.5'):
            r = self.client.get(
                '/taxii2/collections/threat-intel/objects/?limit=' + bad,
                headers=self.auth)
            self.assertEqual(r.status_code, 400, f'limit={bad}')

    def test_bad_since_and_bad_next_400(self):
        self._ingest_n(2)
        r = self.client.get(
            '/taxii2/collections/threat-intel/objects/?since=garbage',
            headers=self.auth)
        self.assertEqual(r.status_code, 400)
        r = self.client.get(
            '/taxii2/collections/threat-intel/objects/?next=%%%',
            headers=self.auth)
        self.assertEqual(r.status_code, 400)

    def test_pagination_respects_match_type(self):
        self._ingest_n(3)
        self.client.post('/feed/ingest', json={'stix_objects': [
            {'id': 'domain-name--a-b', 'type': 'domain-name',
             'object': {'domain-name': {'value': 'a.b'}},
             'labels': [], 'confidence': 50},
            {'id': 'domain-name--c-d', 'type': 'domain-name',
             'object': {'domain-name': {'value': 'c.d'}},
             'labels': [], 'confidence': 50},
        ]}, headers=self.auth)
        msg = self._page('?limit=1&match%5Btype%5D=domain-name')
        objs = msg['content']['content']['objects']
        self.assertEqual(len(objs), 1)
        self.assertTrue(msg['more'])
        # follow to the end — only domains ever returned
        more, nxt = msg['more'], msg.get('next')
        seen = [o['id'] for o in objs]
        while more:
            msg = self._page('?limit=1&match%5Btype%5D=domain-name&next='
                             + urllib.parse.quote(nxt))
            seen.extend(o['id'] for o in msg['content']['content']['objects'])
            more, nxt = msg['more'], msg.get('next')
        self.assertEqual(sorted(seen), ['domain-name--a-b', 'domain-name--c-d'])

    def test_pagination_not_changed_by_since_for_old_rows(self):
        # rows ingested at the same batch share a timestamp; the cursor must
        # still separate them by stix_id (no skipped/duplicate rows).
        self._ingest_n(4)
        msg = self._page('?limit=2')
        objs1 = msg['content']['content']['objects']
        msg2 = self._page('?limit=2&next=' + urllib.parse.quote(msg['next']))
        objs2 = msg2['content']['content']['objects']
        all_ids = [o['id'] for o in objs1] + [o['id'] for o in objs2]
        self.assertEqual(len(set(all_ids)), 4)
        self.assertFalse(msg2['more'])

    def test_multi_value_match_filters(self):
        """match[type]/match[id] accept comma-separated lists (spec 5.3):
        every listed value is a disjunction (a real client joins them this
        way — e.g. taxii2client sends match[type]=domain-name,file-hash)."""
        self._ingest_n(3)
        self.client.post('/feed/ingest', json={'stix_objects': [
            {'id': 'domain-name--a-b', 'type': 'domain-name',
             'object': {'domain-name': {'value': 'a.b'}},
             'labels': [], 'confidence': 50},
        ], 'mode': 'merge'}, headers=self.auth)
        # comma-separated match[type] -> union of the listed types
        objs = self._page(
            '?match%5Btype%5D=domain-name,ipv4-addr')['content']['content']['objects']
        self.assertEqual(len(objs), 4)  # 3 ipv4 + 1 domain
        # comma-separated match[id] -> union of the listed ids
        objs = self._page(
            '?match%5Bid%5D=ipv4-addr--1-1-1-1,domain-name--a-b'
        )['content']['content']['objects']
        self.assertEqual(sorted(o['id'] for o in objs),
                         ['domain-name--a-b', 'ipv4-addr--1-1-1-1'])
        # a non-matching single value is still a real filter (not a no-op)
        objs = self._page('?match%5Btype%5D=nope')['content']['content']['objects']
        self.assertEqual(len(objs), 0)


class TestXlsxImport(unittest.TestCase):
    """Excel (.xlsx) import through /feed/import-csv + column typing."""

    def setUp(self):
        self.client = app.test_client()
        _reset_db()
        app.config['TAXII_AUTH'] = {
            'username': 'test_taxii_user',
            'password': 'test_taxii_pass',
        }
        self.auth = {
            'X-Taxii-Username': 'test_taxii_user',
            'X-Taxii-Password': 'test_taxii_pass',
        }

    def _xlsx_bytes(self, rows):
        """Build an .xlsx workbook in memory: rows[0] = headers."""
        from openpyxl import Workbook
        wb = Workbook()
        ws = wb.active
        for row in rows:
            ws.append([c if c is not None else '' for c in row])
        buf = io.BytesIO()
        wb.save(buf)
        wb.close()
        return buf.getvalue()

    def _post_xlsx(self, rows, filename='intel.xlsx'):
        return self.client.post(
            '/feed/import-csv',
            data={'file': (io.BytesIO(self._xlsx_bytes(rows)), filename)},
            headers=self.auth,
        )

    def test_xlsx_upload_fuzzy_headers(self):
        # Note: "Destination" maps to the IP role (dstip) — a domain there is
        # dropped, exactly like the CSV path. Domains need a 'domain' header.
        r = self._post_xlsx([
            ['IP_Address', 'domain', 'labels', 'confidence'],
            ['1.2.3.4', 'evil.example.com', 'c2', 90],
            ['5.6.7.8', 'bot.evil.net', 'apt', 80],
        ])
        self.assertEqual(r.status_code, 200, r.get_json())
        body = r.get_json()
        self.assertEqual(body['imported'], 4)
        self.assertEqual(body['skipped_total'], 0)
        r = self.client.get('/objects', headers=self.auth)
        objs = r.get_json()['objects']
        self.assertEqual({o['value'] for o in objs},
                         {'1.2.3.4', '5.6.7.8', 'evil.example.com', 'bot.evil.net'})

    def test_xlsx_indicator_column_promotes_url(self):
        r = self._post_xlsx([
            ['indicator', 'labels', 'confidence'],
            ['http://evil.example.com/x', 'url-ioc', 70],
            ['free text note', 'note', 50],
        ])
        self.assertEqual(r.status_code, 200)
        objs = self.client.get('/objects', headers=self.auth).get_json()['objects']
        by_type = {o['type']: o for o in objs}
        self.assertEqual(by_type['url']['value'], 'http://evil.example.com/x')
        self.assertEqual(by_type['indicator']['value'], 'free text note')

    def test_csv_indicator_column_promotes_url_and_ipv6(self):
        r = self.client.post(
            '/feed/import-csv',
            data={'file': (io.BytesIO(
                ('indicator,labels\n'
                 'http://evil.example.com/x,c2\n'
                 '2001:db8::1,ip\n').encode()), 'intel.csv')},
            headers=self.auth,
        )
        self.assertEqual(r.status_code, 200)
        objs = self.client.get('/objects', headers=self.auth).get_json()['objects']
        types = {o['type'] for o in objs}
        self.assertIn('url', types)
        self.assertIn('ipv6-addr', types)

    def test_xlsx_ip_column_accepts_ipv6(self):
        r = self._post_xlsx([
            ['ip'],
            ['2001:db8::42'],
        ])
        self.assertEqual(r.status_code, 200)
        objs = self.client.get('/objects', headers=self.auth).get_json()['objects']
        self.assertEqual(len(objs), 1)
        self.assertEqual(objs[0]['type'], 'ipv6-addr')

    def test_xlsx_bad_file_400(self):
        r = self.client.post(
            '/feed/import-csv',
            data={'file': (io.BytesIO(b'this is not a real xlsx'), 'intel.xlsx')},
            headers=self.auth,
        )
        # unparseable workbook -> no objects -> 400 (or openpyxl error)
        self.assertEqual(r.status_code, 400)


class TestCollectionsRbac(unittest.TestCase):
    """Multi-collection support: per-collection credentials, isolated
    Get Objects, collection-scoped data endpoints, and the legacy
    single-collection default.
    """

    _GLOBALS = ('TAXII_COLLECTIONS', 'TAXII_COLLECTION_MAP',
                'TAXII_COLLECTION_ID', 'TAXII_COLLECTION_TITLE')

    def setUp(self):
        self.client = app.test_client()
        _reset_db()
        self._saved = {k: getattr(_server, k) for k in self._GLOBALS}
        cc = _server.CollectionConfig
        self.coll_a = cc(id='alpha', title='Alpha Feed',
                         description='first',
                         username='a_user', password='a_pass')
        self.coll_b = cc(id='beta', title='Beta Feed',
                         description='second',
                         username='b_user', password='b_pass')
        _server.TAXII_COLLECTIONS = [self.coll_a, self.coll_b]
        _server.TAXII_COLLECTION_MAP = {c.id: c for c in _server.TAXII_COLLECTIONS}
        _server.TAXII_COLLECTION_ID = 'alpha'
        _server.TAXII_COLLECTION_TITLE = 'Alpha Feed'
        # NO global credential override: only per-collection creds exist.
        app.config['TAXII_AUTH'] = {'username': '', 'password': ''}
        self.auth_a = {'X-Taxii-Username': 'a_user', 'X-Taxii-Password': 'a_pass'}
        self.auth_b = {'X-Taxii-Username': 'b_user', 'X-Taxii-Password': 'b_pass'}

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(_server, k, v)

    def _ingest(self, objs, collection, auth):
        return self.client.post(
            '/feed/ingest',
            json={'stix_objects': objs, 'collection': collection},
            headers=auth)

    def test_each_principal_sees_only_its_collection(self):
        self._ingest([_manual_obj('1.1.1.1')], 'alpha', self.auth_a)
        self._ingest([_manual_obj('2.2.2.2')], 'beta', self.auth_b)
        # alpha creds (collection A) list only A
        r = self.client.get('/taxii2/collections/', headers=self.auth_a)
        ids = [c['id'] for c in r.get_json()['collections']]
        self.assertEqual(ids, ['alpha'])
        # beta creds list only B
        r = self.client.get('/taxii2/collections/', headers=self.auth_b)
        ids = [c['id'] for c in r.get_json()['collections']]
        self.assertEqual(ids, ['beta'])

    def test_get_objects_isolated_per_collection(self):
        self._ingest([_manual_obj('1.1.1.1')], 'alpha', self.auth_a)
        self._ingest([_manual_obj('2.2.2.2')], 'beta', self.auth_b)
        # A's creds cannot read B
        r = self.client.get('/taxii2/collections/beta/objects/',
                            headers=self.auth_a)
        self.assertEqual(r.status_code, 401)
        # A's creds read only A's object
        r = self.client.get('/taxii2/collections/alpha/objects/',
                            headers=self.auth_a)
        objs = r.get_json()['content']['content']['objects']
        self.assertEqual(len(objs), 1)
        self.assertEqual(objs[0]['value'], '1.1.1.1')

    def test_unknown_collection_404_and_bad_creds_401(self):
        self._ingest([_manual_obj('1.1.1.1')], 'alpha', self.auth_a)
        r = self.client.get('/taxii2/collections/nope/objects/',
                            headers=self.auth_a)
        self.assertEqual(r.status_code, 404)
        r = self.client.get('/taxii2/collections/nope/',
                            headers=self.auth_a)
        self.assertEqual(r.status_code, 404)
        # wrong creds entirely
        bad = {'X-Taxii-Username': 'x', 'X-Taxii-Password': 'y'}
        r = self.client.get('/taxii2/collections/alpha/objects/', headers=bad)
        self.assertEqual(r.status_code, 401)

    def test_data_endpoints_collection_scoping(self):
        self._ingest([_manual_obj('1.1.1.1')], 'alpha', self.auth_a)
        self._ingest([_manual_obj('2.2.2.2')], 'beta', self.auth_b)
        # /objects defaults to the primary collection (alpha)
        r = self.client.get('/objects', headers=self.auth_a)
        vals = {o['value'] for o in r.get_json()['objects']}
        self.assertEqual(vals, {'1.1.1.1'})
        # ... unless ?collection= says otherwise
        r = self.client.get('/objects?collection=beta', headers=self.auth_b)
        vals = {o['value'] for o in r.get_json()['objects']}
        self.assertEqual(vals, {'2.2.2.2'})
        # unknown collection -> 400
        r = self.client.get('/objects?collection=nope', headers=self.auth_a)
        self.assertEqual(r.status_code, 400)
        # ingest with unknown collection -> 400
        r = self._ingest([_manual_obj('3.3.3.3')], 'nope', self.auth_a)
        self.assertEqual(r.status_code, 400)

    def test_replace_ingest_is_per_collection(self):
        # a replace-save of beta must not touch alpha's manual rows
        self._ingest([_manual_obj('1.1.1.1')], 'alpha', self.auth_a)
        self._ingest([_manual_obj('2.2.2.2')], 'beta', self.auth_b)
        r = self.client.post(
            '/feed/ingest',
            json={'stix_objects': [_manual_obj('9.9.9.9')],
                  'collection': 'beta', 'mode': 'replace'},
            headers=self.auth_b)
        self.assertEqual(r.status_code, 200)
        r = self.client.get('/objects', headers=self.auth_a)
        self.assertEqual({o['value'] for o in r.get_json()['objects']},
                         {'1.1.1.1'})
        r = self.client.get('/objects?collection=beta', headers=self.auth_b)
        self.assertEqual({o['value'] for o in r.get_json()['objects']},
                         {'9.9.9.9'})

    def test_purge_scoped_to_collection(self):
        self._ingest([_manual_obj('1.1.1.1')], 'alpha', self.auth_a)
        self._ingest([_manual_obj('2.2.2.2')], 'beta', self.auth_b)
        r = self.client.delete('/feed/purge?collection=beta',
                               headers=self.auth_b)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['purged'], 1)
        r = self.client.get('/objects', headers=self.auth_a)
        self.assertEqual({o['value'] for o in r.get_json()['objects']},
                         {'1.1.1.1'})

    def test_ui_collections_endpoint(self):
        r = self.client.get('/ui/collections', headers=self.auth_a)
        self.assertEqual(r.status_code, 200)
        ids = [c['id'] for c in r.get_json()['collections']]
        self.assertEqual(ids, ['alpha', 'beta'])
        self.assertEqual(r.get_json()['primary'], 'alpha')

    def test_single_collection_compat_uses_primary(self):
        # With the registry pointing at one collection, the API behaves like
        # the legacy single-collection server.
        _server.TAXII_COLLECTIONS = [self.coll_a]
        _server.TAXII_COLLECTION_MAP = {'alpha': self.coll_a}
        self._ingest([_manual_obj('1.1.1.1')], 'alpha', self.auth_a)
        r = self.client.get('/taxii2/collections/', headers=self.auth_a)
        self.assertEqual(r.get_json()['meta']['count'], 1)
        r = self.client.get('/objects', headers=self.auth_a)
        self.assertEqual(r.get_json()['count'], 1)


class _FakeJwkClient:
    """Stand-in for jwt.PyJWKClient: returns the local public key for any token."""

    def __init__(self, public_key):
        self._pub = public_key

    def get_signing_key_from_jwt(self, token):
        import types
        key = types.SimpleNamespace()
        key.key = self._pub
        return key


if __name__ == '__main__':
    unittest.main(verbosity=2)
