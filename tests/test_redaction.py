import base64
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('exporter', Path(__file__).parents[1] / 'scripts/redaction.py')
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


class DateTests(unittest.TestCase):
    def test_iso_utc(self):
        self.assertEqual(exporter.iso_utc('2026-10-07 03:03:21+08:00'), '2026-10-06T19:03:21+00:00')
        self.assertIsNone(exporter.iso_utc('not a date'))
        self.assertIsNone(exporter.iso_utc(None))


class RedactionTests(unittest.TestCase):
    def test_nested_encoded_payload_and_secret_echo(self):
        secret = 'synthetic-security-code'
        payload = f'<script>window._AMapSecurityConfig={{securityJsCode:"{secret}"}};console.log("{secret}")</script>'
        inner = 'https://httpbin.org/base64/' + base64.b64encode(payload.encode()).decode()
        outer = 'https://httpbin.org/base64/' + base64.urlsafe_b64encode(inner.encode()).decode()
        variants, decoded = exporter.expand(outer)
        self.assertIn(payload, decoded)
        self.assertTrue(any(exporter.AMAP.search(v) for v in variants))
        r = exporter.Redactor()
        r.discover([outer, *decoded])
        output = r.tree([outer, *decoded])
        self.assertNotIn(secret, '\n'.join(output))
        self.assertIn('[REDACTED_BASE64_PAYLOAD]', output[0])

    def test_url_json_and_javascript_escape_forms(self):
        fixtures = [
            ('https://webapi.amap.com/maps?%6b%65%79=synthetic-api-key', 'synthetic-api-key'),
            (r'{\"security\u004asCode\":\"synthetic-escaped-code\"}', 'synthetic-escaped-code'),
            ('{"securityCode":"synthetic-code","api_key":"synthetic-api"}', 'synthetic-code'),
            ('https://user:synthetic-password@example.com/', 'synthetic-password'),
            ('<input name="apiKey" value="synthetic-input-key">', 'synthetic-input-key'),
        ]
        r = exporter.Redactor()
        r.discover(s for s, _ in fixtures)
        for raw, secret in fixtures:
            self.assertNotIn(secret, r.clean(raw))

    def test_short_named_secrets(self):
        fixtures = ['https://webapi.amap.com/maps?key=123', '{"securityJsCode":"abc"}']
        r = exporter.Redactor()
        r.discover(fixtures)
        self.assertNotIn('123', r.clean(fixtures[0]))
        self.assertNotIn('abc', r.clean(fixtures[1]))
        self.assertNotIn('123', r.clean('<input value="123" name="apiKey">'))

    def test_safe_context_is_preserved(self):
        safe = 'https://amap-pc-ssr.amap.com/?url=https://example.com/test'
        r = exporter.Redactor()
        r.discover([safe])
        self.assertEqual(r.clean(safe), safe)

    def test_credential_named_flags_modes_and_counters_are_preserved(self):
        fixtures = ['let x=new XMLHttpRequest;x.withCredentials=true;x.open("GET",u)',
                    "fetch(u,{mode:'no-cors',credentials:'include'})",
                    "init({appendTo:'header',needUmidToken:!0,paramsType:['uab']})",
                    'data.httpStatus=200|data.usage.outputTokens=2634 ~~ rawLength=8598']
        r = exporter.Redactor()
        r.discover(fixtures)
        for raw in fixtures:
            self.assertEqual(r.clean(raw), raw)
        tree = {'withCredentials': True, 'usage': {'outputTokens': 2634}, 'credentials': 'omit'}
        self.assertEqual(r.tree(tree), tree)

    def test_counters_in_a_separated_chain_do_not_hide_later_secrets(self):
        raw = 'data.usage.outputTokens=2634|data.usage.tokens=2634|data.apiKey=synthetic-chained-key-1|data.ok=1'
        r = exporter.Redactor()
        r.discover([raw])
        self.assertEqual(r.clean(raw), 'data.usage.outputTokens=2634|data.usage.tokens=2634|data.apiKey=[REDACTED]')
        self.assertEqual([m['value'] for m in exporter.bare_secrets(raw)], ['synthetic-chained-key-1|data.ok=1'])

    def test_credential_named_values_that_are_not_literals_are_redacted(self):
        fixtures = [('x.withCredentials=synthetic-flag-value', 'synthetic-flag-value'),
                    ("{credentials:'synthetic-user:synthetic-pass'}", 'synthetic-pass'),
                    ('needUmidToken:synthetic-umid', 'synthetic-umid'),
                    ('umidToken=12345', '12345'),
                    ('tokens=synthetic-list', 'synthetic-list')]
        r = exporter.Redactor()
        r.discover(s for s, _ in fixtures)
        for raw, secret in fixtures:
            self.assertNotIn(secret, r.clean(raw))
        self.assertEqual(r.tree({'credentials': 'synthetic-pass', 'outputTokens': 'synthetic-list'}),
                         {'credentials': '[REDACTED]', 'outputTokens': '[REDACTED]'})


if __name__ == '__main__':
    unittest.main()
