import base64
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
import export_findings_amap as exporter


class FindingsTests(unittest.TestCase):
    def test_proxy_and_nested_payloads(self):
        secret = 'fake-security-code-12345'
        payload = '<script>window._AMapSecurityConfig={securityJsCode:"' + secret + '"};</script>'
        inner = 'https://httpbin.org/base64/' + base64.b64encode(payload.encode()).decode()
        proxy = 'https://api.allorigins.win/raw?url=' + quote(inner, safe='')
        r = exporter.Evidence()
        rid = '00000000-0000-4000-8000-000000000001'
        r.add(rid, {'report_id': rid, 'submitted_url': proxy}, 'sample.json')
        record = r.reports[rid]
        self.assertTrue(record['match_basis'])
        self.assertIn(payload, record['decoded'])
        redactor = exporter.Redactor()
        redactor.discover(exporter.strings(exporter.serializable(record)))
        safe = redactor.tree(exporter.serializable(record))
        self.assertNotIn(secret, json.dumps(safe))
        self.assertNotIn(base64.b64encode(payload.encode()).decode(), json.dumps(safe))
        self.assertFalse(any(exporter.audit(safe).values()))

    def test_labels_do_not_qualify_a_report(self):
        r = exporter.Evidence()
        rid = '00000000-0000-4000-8000-000000000002'
        r.add(rid, {'id': rid, 'url': 'https://example.com/', 'queries': ['amap'],
                    'source_file': '/amap-followup/something.json'}, 'amap-search.json')
        self.assertFalse(r.reports[rid]['match_basis'])

    def test_short_and_escaped_credentials(self):
        fixtures = ['https://webapi.amap.com/maps?%6b%65%79=abc',
                    r'{\"security\u004asCode\":\"tiny\"}',
                    '<input name="apiKey" value="123">']
        r = exporter.Redactor()
        r.discover(fixtures)
        safe = r.tree(fixtures)
        for secret in ('abc', 'tiny', '123'):
            self.assertNotIn(secret, json.dumps(safe))
        self.assertFalse(any(exporter.audit(safe).values()))

    def test_scan_columns_from_capture(self):
        final = 'https://www.amap.com/place/B000'
        capture = {
            'submit': {}, 'final': {'url': {'addr': final}}, 'tags': None,
            'ip': {'addr': '192.0.2.1', 'asn': 64500, 'as': 'EXAMPLE', 'country_code': 'CN'},
            'settings': {'access': 'public', 'useragent': 'UA', 'referer': '', 'exit_node': 'NO'},
            'stats': {'alert_count': {'ids': 1, 'urlquery': 2, 'analyzer': 0}},
            'http': [{'url': {'addr': 'https://example.com/a.js'}, 'response': {'status_code': '200'}},
                     {'url': {'addr': final}, 'is_navigation_request': True, 'response': {'status_code': '302'}},
                     {'url': {'addr': final}, 'is_navigation_request': True, 'ip': {'addr': '192.0.2.2'},
                      'resource_type': 'document', 'response': {'status_code': '200'}}],
        }
        fields = exporter.scan_fields(capture)
        self.assertEqual((fields['final_status'], fields['alert_count'], fields['requests_total']), (200, 3, 3))
        self.assertIsNone(fields['referer'])
        self.assertEqual(fields['tags'], [])
        r = exporter.Evidence()
        rid = '00000000-0000-4000-8000-000000000004'
        r.add(rid, {'report_id': rid, **capture}, 'sample.json')
        self.assertEqual(r.reports[rid]['server_ip'], '192.0.2.1')
        request = next(q for q in r.reports[rid]['requests'].values() if q['ordinal'] == 2)
        self.assertEqual((request['ip'], request['resource_type'], request['navigation']), ('192.0.2.2', 'document', True))

    def test_scanned_at_is_normalized_utc(self):
        self.assertEqual(exporter.earliest(['2026-10-07 03:03']), '2026-10-07T03:03:00+00:00')
        # A minute-only listing date must not outrank a precise capture time.
        self.assertEqual(exporter.earliest(['2026-10-04 01:00', '2026-10-07T03:03:21Z', '2026-10-07 03:03:40+00:00']),
                         '2026-10-07T03:03:21+00:00')
        self.assertIsNone(exporter.earliest([]))

    def test_listing_and_capture_merge(self):
        rid = '00000000-0000-4000-8000-000000000003'
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'urlquery-listing.json').write_text(json.dumps({rid: {'id': rid, 'url': 'https://example.com/'}}))
            (root / (rid + '.json')).write_text(json.dumps({'report_id': rid, 'submit': {'url': 'https://example.com/'},
                'http': [{'url': {'addr': 'https://restapi.amap.com/v3/place/detail?key=synthetic'},
                          'request': {'method': 'GET'}, 'response': {'status_code': '200'}}]}))
            rows = exporter.Evidence().load(root)
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0]['source_files']), 2)
        self.assertTrue(rows[0]['raw_capture_available'])


if __name__ == '__main__':
    unittest.main()
