#!/usr/bin/env python3
"""Export locally archived Amap webhook requests and cached ntfy attachments."""
from __future__ import annotations

import collections
import gzip
import hashlib
import json
from pathlib import Path
import re
import sqlite3

from export_findings_amap import UUID, audit
from export_ntfy_amap import ARCHIVER, FINDINGS, LEADS, OUTPUT, canonical, parse_text
from redaction import Redactor, expand, strings

ROOTS = {'findings': FINDINGS, 'hosted_probe_leads': LEADS, 'ntfy_archiver': ARCHIVER}
MAILBOX_URL = re.compile(r'webhook\.site/(?:token/)?(' + UUID.pattern + r')', re.I)


def public_id(value):
    return value.lower() if isinstance(value, str) and UUID.fullmatch(value) else None


def native_requests(value, pointer='', depth=0):
    if depth > 18:
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            yield from native_requests(item, pointer + '/' + str(i), depth + 1)
    elif isinstance(value, dict):
        if public_id(value.get('uuid')) and public_id(value.get('token_id')) and any(k in value for k in ('content', 'headers', 'method')):
            yield value, pointer or '/'
            return
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                yield from native_requests(item, pointer + '/' + str(key), depth + 1)
            elif key in ('event_json', 'raw_ndjson_utf8') and isinstance(item, str):
                for parsed in parse_text(item):
                    yield from native_requests(parsed, pointer + '/' + str(key) + '/embedded_json', depth + 1)


def native_configurations(value, pointer='', depth=0):
    if depth > 18:
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            yield from native_configurations(item, pointer + '/' + str(i), depth + 1)
    elif isinstance(value, dict):
        if public_id(value.get('uuid')) and ('default_content' in value or 'default_status' in value):
            yield value, pointer or '/'
            return
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                yield from native_configurations(item, pointer + '/' + str(key), depth + 1)


def clean_provenance(provenance, redactor):
    result = dict(provenance)
    result['file'] = '/'.join(redactor.clean(p) for p in result['file'].split('/'))
    if 'origin' in result:
        result['origin'] = redactor.clean(result['origin'])
    return result


class Webhooks:
    def __init__(self):
        self.scope = collections.defaultdict(set)
        self.report_links = collections.defaultdict(set)
        self.records = {}
        self.configurations = {}
        self.blobs = {}
        self.stats = collections.Counter()
        self.errors = []
        # These two saved configuration decisions explicitly identify Amap collectors.
        for name in ('20261007T000416Z-amap-webhooks-added.json', '20261007T1635Z-mochou-webhook-added.json'):
            d = json.loads((ARCHIVER / 'topic-additions' / name).read_text())
            for mailbox in d.get('added_mailboxes', []) + ([d['mailbox']] if 'mailbox' in d else []):
                match = MAILBOX_URL.search(mailbox)
                if match:
                    self.scope[match[1].lower()].add('archiver_amap_collection_configuration')
        payloads = {p['payload_id']: p['decoded_content_redacted']
                    for p in map(json.loads, (OUTPUT / 'payloads.jsonl').open())}
        for line in (OUTPUT / 'reports.jsonl').open():
            report = json.loads(line)
            decoded = [payloads[pid] for pid in report['decoded_payload_ids']]
            for text in strings([{k: v for k, v in report.items() if k != 'source_files'}, decoded]):
                for mailbox in MAILBOX_URL.findall(text):
                    mailbox = mailbox.lower()
                    self.scope[mailbox].add('referenced_by_existing_amap_report')
                    self.report_links[mailbox].add(report['report_id'])
        # Explicitly classified other-target collectors must not enter this Amap export.
        excluded = FINDINGS / 'amap-webhooks-2026-10-04/captures/coordination-audit/other-channels'
        self.excluded = set()
        for path in excluded.glob('cancer*metadata.json'):
            mailbox = public_id(json.loads(path.read_text()).get('uuid'))
            if mailbox and 'archiver_amap_collection_configuration' not in self.scope[mailbox]:
                self.excluded.add(mailbox)
                self.scope.pop(mailbox, None)

    def add(self, request, source):
        mailbox = public_id(request.get('token_id'))
        if mailbox not in self.scope:
            return None
        key = canonical(request)
        value = self.records.setdefault(key, {'request': request, 'sources': {}})
        value['sources'][canonical(source)] = source
        return key

    def blob(self, data, source):
        self.stats['files_considered'] += 1
        is_request = b'"token_id"' in data and b'"uuid"' in data
        is_config = b'"uuid"' in data and (b'"default_content"' in data or b'"default_status"' in data)
        if not is_request and not is_config:
            return
        digest = hashlib.sha256(data).digest()
        if digest in self.blobs:
            for kind, key, pointer in self.blobs[digest]:
                p = {**source, 'json_pointer': pointer}
                collection = self.records if kind == 'request' else self.configurations
                collection[key]['sources'][canonical(p)] = p
            self.stats['duplicate_files'] += 1
            return
        refs = set()
        for obj in parse_text(data.decode('utf-8-sig', errors='replace')):
            if is_request:
                for request, pointer in native_requests(obj):
                    key = self.add(request, {**source, 'json_pointer': pointer})
                    if key:
                        refs.add(('request', key, pointer))
            if is_config:
                for config, pointer in native_configurations(obj):
                    if public_id(config['uuid']) not in self.scope:
                        continue
                    key = canonical(config)
                    row = self.configurations.setdefault(key, {'configuration': config, 'sources': {}})
                    p = {**source, 'json_pointer': pointer}
                    row['sources'][canonical(p)] = p
                    refs.add(('configuration', key, pointer))
        self.blobs[digest] = refs

    def scan(self):
        for label, root in ROOTS.items():
            if label == 'ntfy_archiver':
                self.blob((root / 'state/messages.ndjson').read_bytes(), {'root': label, 'file': 'state/messages.ndjson'})
                continue
            for path in sorted(root.rglob('*')):
                if not path.is_file() or path.suffix not in ('.json', '.jsonl', '.ndjson', '.body', '.txt', '.gz'):
                    continue
                if path.suffix == '.gz' and not path.name.endswith(('.json.gz', '.jsonl.gz')):
                    continue
                try:
                    data = path.read_bytes()
                    if path.suffix == '.gz':
                        data = gzip.decompress(data)
                    self.blob(data, {'root': label, 'file': path.relative_to(root).as_posix()})
                except (ValueError, OSError, EOFError) as exc:
                    self.errors.append({'root': label, 'file': path.relative_to(root).as_posix(), 'error_type': type(exc).__name__})
        db = ARCHIVER / 'state/archive.sqlite3'
        wal = Path(str(db) + '-wal')
        if not wal.exists() or not wal.stat().st_size:
            with sqlite3.connect(db.as_uri() + '?mode=ro&immutable=1', uri=True) as connection:
                connection.execute('PRAGMA query_only=ON')
                for event, received, origin in connection.execute('SELECT event_json,received,origin FROM events'):
                    event = json.loads(event)
                    if event.get('event') == 'webhook_request':
                        self.add(event['webhook_request'], {'root': 'ntfy_archiver', 'file': 'state/archive.sqlite3',
                                 'table': 'events', 'received_at': received, 'origin': origin})
        else:
            self.errors.append({'root': 'ntfy_archiver', 'file': 'state/archive.sqlite3', 'note': 'Active WAL: used saved NDJSON.'})

    def export(self):
        values = list(self.records.values())
        print(f'Loaded {len(values):,} distinct archived webhook request versions. Redacting.', flush=True)
        raw = []
        for value in values:
            _, decoded = expand(value['request'].get('content') or '') if isinstance(value['request'].get('content'), str) else (None, [])
            raw.append({'request': value['request'], 'decoded_payloads': sorted(set(decoded))})
        redactor = Redactor()
        redactor.discover([canonical(raw), canonical([v['configuration'] for v in self.configurations.values()]), *strings(raw)])
        merged = {}
        for value, item in zip(values, raw, strict=True):
            mailbox = public_id(value['request']['token_id'])
            request_id = public_id(value['request']['uuid'])
            safe = redactor.tree(redactor.tree(item))
            safe.update({'mailbox_id': mailbox, 'mailbox_url': 'https://webhook.site/' + mailbox,
                         'request_id': request_id, 'match_basis': sorted(self.scope[mailbox])})
            rid = 'webhook-' + hashlib.sha256(canonical(safe).encode()).hexdigest()[:24]
            row = merged.setdefault(rid, {**safe, 'record_id': rid, 'provenance': {}})
            for source in value['sources'].values():
                source = clean_provenance(source, redactor)
                row['provenance'][canonical(source)] = source
        rows = []
        for row in merged.values():
            row['provenance'] = sorted(row['provenance'].values(), key=canonical)
            rows.append(row)
        rows.sort(key=lambda r: (r['request'].get('created_at') or '', r['mailbox_id'], r['request_id'], r['record_id']))
        checks = audit(rows)
        assert not any(checks.values()), 'Webhook redaction audit failed (counts only): ' + canonical(checks)
        configs = {}
        for value in self.configurations.values():
            config = value['configuration']
            mailbox = public_id(config['uuid'])
            content = config.get('default_content')
            _, decoded = expand(content) if isinstance(content, str) else (None, [])
            safe = redactor.tree(redactor.tree({'configuration': config, 'decoded_payloads': sorted(set(decoded))}))
            safe.update({'mailbox_id': mailbox, 'match_basis': sorted(self.scope[mailbox])})
            rid = 'webhook-config-' + hashlib.sha256(canonical(safe).encode()).hexdigest()[:24]
            row = configs.setdefault(rid, {**safe, 'record_id': rid, 'provenance': {}})
            for source in value['sources'].values():
                source = clean_provenance(source, redactor)
                row['provenance'][canonical(source)] = source
        config_rows = []
        for row in configs.values():
            row['provenance'] = sorted(row['provenance'].values(), key=canonical)
            config_rows.append(row)
        config_rows.sort(key=lambda r: (r['mailbox_id'], r['configuration'].get('updated_at') or '', r['record_id']))
        checks = audit([rows, config_rows])
        assert not any(checks.values()), 'Webhook/configuration redaction audit failed (counts only): ' + canonical(checks)
        mailboxes = []
        for mailbox in sorted(self.scope):
            subset = [r for r in rows if r['mailbox_id'] == mailbox]
            mailboxes.append({'mailbox_id': mailbox, 'mailbox_url': 'https://webhook.site/' + mailbox,
                              'request_versions': len(subset), 'unique_requests': len({r['request_id'] for r in subset}),
                              'configuration_versions': sum(r['mailbox_id'] == mailbox for r in config_rows),
                              'match_basis': sorted(self.scope[mailbox]),
                              'urlquery_report_ids_in_export': sorted(self.report_links[mailbox])})
        write_jsonl('webhook-requests.jsonl', rows)
        write_jsonl('webhook-mailboxes.jsonl', mailboxes)
        write_jsonl('webhook-configurations.jsonl', config_rows)
        return {'request_versions': len(rows), 'unique_requests': len({(r['mailbox_id'], r['request_id']) for r in rows}),
                'configuration_versions': len(config_rows),
                'mailboxes_with_captures': sum(bool(m['request_versions']) for m in mailboxes),
                'mailboxes_in_scope': len(mailboxes), 'source_file_stats': dict(self.stats),
                'unreadable_files': self.errors, 'redaction_audit': checks}


def write_jsonl(name, rows):
    with (OUTPUT / name).open('w', encoding='utf-8') as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, separators=(',', ':')) + '\n')


def attachments():
    messages = [json.loads(line) for line in (OUTPUT / 'ntfy-messages.jsonl').open()]
    references = collections.defaultdict(list)
    for message in messages:
        attachment = message.get('attachment')
        if isinstance(attachment, dict) and attachment.get('url'):
            references[attachment['url']].append(message)
    output = []
    for url, linked in sorted(references.items()):
        filename = url.rsplit('/', 1)[-1]
        aid = filename.split('.')[0]
        candidates = []
        metadata_sources = []
        metadata = []
        for label, root in ROOTS.items():
            for path in root.rglob('*' + aid + '*'):
                if not path.is_file():
                    continue
                source = {'root': label, 'file': path.relative_to(root).as_posix()}
                if path.name.endswith('.metadata.json'):
                    doc = json.loads(path.read_text())
                    if doc.get('url') == url:
                        metadata.append(doc)
                        metadata_sources.append(source)
                elif path.suffix in ('.txt', '.body', '.bin'):
                    candidates.append((path.read_bytes(), source))
        by_content = collections.defaultdict(list)
        for data, source in candidates:
            by_content[data].append(source)
        if not by_content:
            output.append({'attachment_id': aid, 'source_url': url, 'content_available': False,
                           'ntfy_record_ids': sorted(m['record_id'] for m in linked),
                           'reason': 'Attachment metadata exists, but no cached local content was found.'})
        for data, sources in by_content.items():
            expected_sizes = {m['attachment'].get('size') for m in linked if m['attachment'].get('size') is not None}
            assert not expected_sizes or len(data) in expected_sizes, 'Cached attachment size mismatch'
            hashes = {m['sha256'] for m in metadata if m.get('sha256')}
            assert not hashes or hashlib.sha256(data).hexdigest() in hashes, 'Cached attachment checksum mismatch'
            text = data.decode('utf-8-sig')
            redactor = Redactor()
            redactor.discover([text])
            safe = redactor.tree(redactor.tree({'decoded_content_redacted': text}))
            safe.update({'attachment_id': aid, 'source_url': url, 'content_available': True,
                         'source_size_bytes': len(data), 'cached_checksum_verified': bool(hashes),
                         'ntfy_record_ids': sorted(m['record_id'] for m in linked),
                         'ntfy_message_ids': sorted(m['message_id'] for m in linked),
                         'topics': sorted({m['topic'] for m in linked}),
                         'provenance': [clean_provenance(p, redactor) for p in sources + metadata_sources]})
            safe['record_id'] = 'attachment-' + hashlib.sha256(canonical(safe).encode()).hexdigest()[:24]
            output.append(safe)
    checks = audit(output)
    assert not any(checks.values()), 'Attachment redaction audit failed (counts only): ' + canonical(checks)
    write_jsonl('ntfy-attachments.jsonl', output)
    return {'referenced_attachments': len(references), 'attachment_records': len(output),
            'cached_attachments_exported': sum(a['content_available'] for a in output), 'redaction_audit': checks}


def main():
    print('Merging local Amap webhook captures and saved ntfy attachments.', flush=True)
    collection = Webhooks()
    collection.scan()
    summary = {'webhooks': collection.export(), 'attachments': attachments(),
               'roots': {k: str(v) for k, v in ROOTS.items()},
               'methodology': ['Only saved local archives are read; no database export is imported.',
                               'Mailbox scope comes from saved Amap archiver decisions and links in the existing Amap report collection; explicitly classified cancer collectors are excluded.',
                               'Webhook request objects are deduplicated across captures; changed objects retain distinct versions. Redacted identical versions are merged.',
                               'Public mailbox and request identifiers remain available for joins; authentication headers, API keys and security codes are redacted.',
                               'Attachment content is linked to retained ntfy messages and verified against saved size/checksum metadata before redaction.',
                               'No remote mailbox requests, attachment fetches, or S3 downloads are performed.']}
    (OUTPUT / 'webhook-attachments-summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k != 'methodology'}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
