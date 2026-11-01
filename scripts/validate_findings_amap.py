#!/usr/bin/env python3
"""Validate the exported files without displaying sensitive source values."""
import hashlib
import json
from pathlib import Path

import re

from export_findings_amap import UUID, audit

ISO_UTC = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00')
root = Path('data/amap-findings')
summary = json.loads((root / 'summary.json').read_text())
source = Path(summary['source_directory'])
rows = [json.loads(line) for line in (root / 'reports.jsonl').open()]
catalogue = [json.loads(line) for line in (root / 'payloads.jsonl').open()]
payloads = {p['payload_id']: p for p in catalogue}
assert len(rows) == summary['reports']
assert len(payloads) == len(catalogue) == summary['unique_decoded_payloads']
ids = {r['report_id'] for r in rows}
assert len(ids) == len(rows), 'Duplicate report IDs'
reverse = {pid: set() for pid in payloads}
paths = set()
for row in rows:
    assert UUID.fullmatch(row['report_id']), 'Invalid report ID'
    assert row['report_url'] == 'https://urlquery.net/report/' + row['report_id']
    assert row['scanned_at'] is None or ISO_UTC.fullmatch(row['scanned_at']), 'Invalid scan time'
    assert not row['raw_capture_available'] or row['server_ip'], 'Missing scan columns'
    assert row['match_basis'], 'Missing selection evidence'
    assert row['source_files'], 'Missing provenance'
    paths.update(row['source_files'])
    for pid in row['decoded_payload_ids']:
        reverse[pid].add(row['report_id'])
for pid, p in payloads.items():
    assert pid == 'payload-' + hashlib.sha256(p['decoded_content_redacted'].encode()).hexdigest()[:20]
    assert reverse[pid] == set(p['report_ids']), 'Payload reverse mapping mismatch'
    assert reverse[pid], 'Unreferenced payload'
missing_paths = sum(not (source / path).is_file() for path in paths if '[REDACTED' not in path)
assert not missing_paths, 'Invalid source-file paths'
assert not (root / 'reports.csv').exists(), 'Only JSONL should be exported'
checks = audit([rows, catalogue])
assert not any(checks.values()), 'Redaction audit failed (counts only): ' + json.dumps(checks)
print(json.dumps({'reports': len(rows), 'distinct_payloads': len(payloads),
                  'source_files': len(paths), 'missing_source_files': missing_paths,
                  'redaction_audit': checks}))
