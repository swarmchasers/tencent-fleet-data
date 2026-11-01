#!/usr/bin/env python3
"""Check webhook/attachment coverage, joins, provenance and redaction."""
import json
import sqlite3

from export_webhooks_attachments import ARCHIVER, OUTPUT, ROOTS, UUID, audit


def read(name):
    return [json.loads(line) for line in (OUTPUT / name).open()]


requests = read('webhook-requests.jsonl')
mailboxes = read('webhook-mailboxes.jsonl')
configs = read('webhook-configurations.jsonl')
attachments = read('ntfy-attachments.jsonl')
messages = {r['record_id']: r for r in read('ntfy-messages.jsonl')}
reports = {r['report_id'] for r in read('reports.jsonl')}
summary = json.loads((OUTPUT / 'webhook-attachments-summary.json').read_text())
assert len(requests) == summary['webhooks']['request_versions']
assert len(configs) == summary['webhooks']['configuration_versions']
assert len(attachments) == summary['attachments']['attachment_records']
index = {m['mailbox_id']: m for m in mailboxes}
assert len(index) == len(mailboxes)
for values in (requests, configs, attachments):
    assert len({r['record_id'] for r in values}) == len(values), 'Duplicate record IDs'
    for row in values:
        for source in row.get('provenance', []):
            assert (ROOTS[source['root']] / source['file']).is_file() or '[REDACTED' in source['file'], 'Missing provenance file'
for row in requests:
    assert UUID.fullmatch(row['mailbox_id']) and UUID.fullmatch(row['request_id'])
    assert row['mailbox_id'] in index
    assert row['mailbox_url'] == 'https://webhook.site/' + row['mailbox_id']
for row in configs:
    assert row['mailbox_id'] in index
for mailbox, m in index.items():
    assert m['request_versions'] == sum(r['mailbox_id'] == mailbox for r in requests)
    assert m['unique_requests'] == len({r['request_id'] for r in requests if r['mailbox_id'] == mailbox})
    assert m['configuration_versions'] == sum(r['mailbox_id'] == mailbox for r in configs)
    assert set(m['urlquery_report_ids_in_export']) <= reports
for row in attachments:
    assert row['content_available'] and row['cached_checksum_verified']
    assert row['decoded_content_redacted']
    for rid in row['ntfy_record_ids']:
        assert rid in messages
        assert messages[rid]['attachment']['url'] == row['source_url']
db = ARCHIVER / 'state/archive.sqlite3'
with sqlite3.connect(db.as_uri() + '?mode=ro&immutable=1', uri=True) as connection:
    archived = [json.loads(row[0]) for row in connection.execute('SELECT event_json FROM events')]
baseline = {(r['topic'], r['id']) for r in archived if r.get('event') == 'webhook_request' and r['topic'] in index}
exported = {(r['mailbox_id'], r['request_id']) for r in requests}
assert baseline <= exported, 'Missing locally archived webhook requests'
checks = audit([requests, configs, attachments, mailboxes])
assert not any(checks.values()), 'Redaction audit failed (counts only): ' + json.dumps(checks)
assert not list(OUTPUT.glob('*.csv')), 'JSONL exports only'
print(json.dumps({'webhook_requests': len(exported), 'local_archiver_requests_covered': len(baseline),
                  'configuration_versions': len(configs), 'attachments': len(attachments),
                  'redaction_audit': checks}))
