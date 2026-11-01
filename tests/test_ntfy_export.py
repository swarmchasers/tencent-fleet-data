import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
import export_ntfy_amap as exporter


class NtfyExportTests(unittest.TestCase):
    def test_scope_excludes_other_targets(self):
        self.assertIsNone(exporter.topic_name('bcc-mort-9f3a7c2e1d'))
        self.assertEqual(exporter.topic_name('https://ntfy.sh/' + exporter.TOPICS[0]), exporter.TOPICS[0])
        self.assertEqual(list(exporter.events({'topic': 'bcc-mort-9f3a7c2e1d', 'message': 'test'})), [])

    def test_id_alias_and_exact_observation_reconciliation(self):
        c = exporter.Collection(report_ids=[])
        event = {'topic': exporter.TOPICS[0], 'id': 'synthetic-id', 'time': 1791252000, 'message': 'same content'}
        c.add(event, {'root': 'test', 'file': 'raw.json'})
        c.add({**{k: v for k, v in event.items() if k != 'id'}, 'msg_id': 'synthetic-id'}, {'root': 'test', 'file': 'watch.json'})
        c.add({k: v for k, v in event.items() if k != 'id'}, {'root': 'test', 'file': 'receipt.json'})
        c.reconcile_observations()
        self.assertEqual(len(c.messages), 1)
        self.assertEqual(len(next(iter(c.messages.values()))['provenance']), 3)

    def test_changed_content_and_ambiguous_observations_survive(self):
        c = exporter.Collection(report_ids=[])
        event = {'topic': exporter.TOPICS[0], 'id': 'first-id', 'time': 1791252000, 'message': 'repeated'}
        c.add(event, {'root': 'test', 'file': 'raw.json'})
        c.add({**event, 'message': 'changed'}, {'root': 'test', 'file': 'changed.json'})
        c.add({**event, 'id': 'second-id'}, {'root': 'test', 'file': 'second.json'})
        c.add({k: v for k, v in event.items() if k != 'id'}, {'root': 'test', 'file': 'receipt.json'})
        c.reconcile_observations()
        self.assertEqual(len(c.messages), 4)


if __name__ == '__main__':
    unittest.main()
