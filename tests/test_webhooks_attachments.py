import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
import export_webhooks_attachments as exporter


class WebhookAttachmentTests(unittest.TestCase):
    def test_native_request_and_configuration_are_distinct(self):
        request = {'uuid': '00000000-0000-4000-8000-000000000001',
                   'token_id': '00000000-0000-4000-8000-000000000002', 'content': 'recorded body'}
        config = {'uuid': request['token_id'], 'default_content': 'saved response', 'password': 'synthetic-password'}
        archive = {'data': [request], 'metadata': config}
        self.assertEqual(list(exporter.native_requests(archive)), [(request, '/data/0')])
        self.assertEqual(list(exporter.native_configurations(archive)), [(config, '/metadata')])
        self.assertEqual(list(exporter.native_requests({'uuid': request['uuid'], 'content': 'unbound'})), [])

    def test_structured_secret_is_removed_from_body_echo(self):
        secret = 'synthetic-api-secret-12345'
        request = {'headers': {'x-api-key': secret}, 'content': 'Echo: ' + secret}
        redactor = exporter.Redactor()
        redactor.discover([exporter.canonical(request), *exporter.strings(request)])
        safe = redactor.tree(redactor.tree(request))
        self.assertNotIn(secret, json.dumps(safe))
        self.assertFalse(any(exporter.audit(safe).values()))


if __name__ == '__main__':
    unittest.main()
