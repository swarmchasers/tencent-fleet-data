#!/usr/bin/env python3
"""Merge saved Amap ntfy messages locally; redact before exporting JSONL."""
from __future__ import annotations

import collections
import datetime as dt
import gzip
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import zipfile

from export_findings_amap import UUID, REPORT_URL, audit, records
from redaction import Redactor, expand, strings

FINDINGS = Path('/Users/concurrent/Projects/oai-scraping-test/findings')
ARCHIVER = Path('/Users/concurrent/Projects/chinese-swarm/ntfy-archiver')
LEADS = Path('/Users/concurrent/Projects/chinese-swarm/hosted-probe-leads')
OUTPUT = Path('data/amap-findings')
TOPICS = ('shmq-1791251472-a7x', 'amapmc1791285782')
TOPIC_BYTES = tuple(t.encode() for t in TOPICS)
CONTENT_FIELDS = ('message', 'title', 'tags', 'attachment', 'priority', 'click', 'actions', 'encoding')


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def iso_time(value):
    if isinstance(value, (int, float)):
        try:
            return dt.datetime.fromtimestamp(value, dt.timezone.utc).isoformat()
        except (ValueError, OverflowError, OSError):
            return None
    return None


def topic_name(value):
    if isinstance(value, str):
        for topic in TOPICS:
            if value == topic or value.rstrip('/') == 'https://ntfy.sh/' + topic:
                return topic
    return None


def core_event(event):
    timestamp = event.get('time')
    if timestamp is None and isinstance(event.get('published_at_utc'), str):
        try:
            parsed = dt.datetime.fromisoformat(event['published_at_utc'].replace('Z', '+00:00'))
            if parsed.tzinfo is not None:
                timestamp = int(parsed.timestamp())
        except ValueError:
            pass
    core = {'topic': topic_name(event.get('topic')),
            'message_id': event.get('id') or event.get('msg_id') or event.get('message_id'),
            'event_type': event.get('event') or 'message', 'unix_time': timestamp}
    core.update({k: event.get(k) for k in CONTENT_FIELDS if event.get(k) is not None})
    return core


def parse_text(text):
    try:
        yield json.loads(text)
        return
    except ValueError:
        pass
    for line in text.splitlines():
        line = line.removeprefix('data:').strip()
        if not line or line[:1] not in ('{', '['):
            continue
        try:
            yield json.loads(line)
        except ValueError:
            pass


def events(value, pointer='', depth=0):
    if depth > 12:
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            yield from events(item, pointer + '/' + str(i), depth + 1)
    elif isinstance(value, dict):
        topic = topic_name(value.get('topic'))
        if topic and isinstance(value.get('message'), str) and value.get('event', 'message') not in ('open', 'keepalive', 'webhook_request'):
            yield value, pointer or '/'
            return
        if topic and value.get('event') in ('clear', 'delete'):
            yield value, pointer or '/'
            return
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                yield from events(item, pointer + '/' + str(key), depth + 1)
            elif isinstance(item, str) and any(t in item for t in TOPICS) and item.lstrip()[:1] in ('{', '['):
                for parsed in parse_text(item):
                    yield from events(parsed, pointer + '/' + str(key) + '/embedded_json', depth + 1)


class Collection:
    def __init__(self, report_ids=None):
        self.messages = {}
        self.stats = collections.Counter()
        self.parse_notes = []
        self.topic_reports = {t: set() for t in TOPICS}
        self.report_ids = set(report_ids) if report_ids is not None else {json.loads(line)['report_id'] for line in (OUTPUT / 'reports.jsonl').open()}
        self.blobs = {}

    def add(self, event, provenance):
        topic = topic_name(event.get('topic'))
        core = core_event(event)
        key = canonical(core)
        item = self.messages.setdefault(key, {'core': core, 'provenance': set(), 'expires': set(), 'observations': set()})
        item['provenance'].add(canonical(provenance))
        if event.get('expires') is not None:
            item['expires'].add(event['expires'])
        for field in ('first_observed_at', 'observed_at', 'received_at'):
            if isinstance(event.get(field), str):
                item['observations'].add(event[field])

    def document(self, obj, source):
        found = set()
        for event, pointer in events(obj):
            self.add(event, {**source, 'json_pointer': pointer})
            core = core_event(event)
            found.add(canonical(core))
        # These are topic-level relationships. They do not attribute individual messages.
        for rid, report in records(obj, context=True):
            if rid not in self.report_ids:
                continue
            for value in strings(report):
                for topic in TOPICS:
                    if topic in value:
                        self.topic_reports[topic].add(rid)
        return found

    def reconcile_observations(self):
        index = collections.defaultdict(list)
        for key, item in self.messages.items():
            core = item['core']
            if core['message_id']:
                index[(core['topic'], core['unix_time'], core.get('message'))].append(key)
        for key, item in list(self.messages.items()):
            core = item['core']
            if core['message_id'] or core['unix_time'] is None:
                continue
            candidates = index.get((core['topic'], core['unix_time'], core.get('message')), [])
            candidates = [k for k in candidates if all(self.messages[k]['core'].get(field) == value
                          for field, value in core.items() if field != 'message_id')]
            if len(candidates) == 1:
                target = self.messages[candidates[0]]
                for field in ('provenance', 'observations', 'expires'):
                    target[field].update(item[field])
                del self.messages[key]
                self.stats['idless_observations_linked_by_exact_topic_time_content'] += 1

    def blob(self, data, source):
        self.stats['files_considered'] += 1
        if not any(t in data for t in TOPIC_BYTES):
            return
        self.stats['files_with_amap_topic_reference'] += 1
        digest = hashlib.sha256(data).digest()
        if digest in self.blobs:
            for key, pointer in self.blobs[digest]:
                self.messages[key]['provenance'].add(canonical({**source, 'json_pointer': pointer}))
            self.stats['duplicate_files'] += 1
            return
        text = data.decode('utf-8-sig', errors='replace')
        indexes = set()
        for obj in parse_text(text):
            keys = self.document(obj, source)
            for key in keys:
                for p in self.messages[key]['provenance']:
                    p = json.loads(p)
                    if p.get('root') == source['root'] and p.get('file') == source['file']:
                        indexes.add((key, p['json_pointer']))
        self.blobs[digest] = indexes

    def scan(self):
        for root_name, root in (('findings', FINDINGS), ('hosted_probe_leads', LEADS)):
            for path in sorted(root.rglob('*')):
                if not path.is_file() or path.suffix not in ('.json', '.jsonl', '.ndjson', '.body', '.txt', '.gz'):
                    continue
                if path.suffix == '.gz' and not path.name.endswith(('.json.gz', '.jsonl.gz')):
                    continue
                rel = path.relative_to(root).as_posix()
                if root_name == 'hosted_probe_leads' and not any(t in rel.lower() for t in ('ntfy', 'shmq', 'amapmc')):
                    continue
                try:
                    data = path.read_bytes()
                    if path.suffix == '.gz':
                        data = gzip.decompress(data)
                    self.blob(data, {'root': root_name, 'file': rel})
                except (ValueError, OSError, EOFError) as exc:
                    self.parse_notes.append({'root': root_name, 'file': rel, 'error_type': type(exc).__name__})
        self.blob((ARCHIVER / 'state/messages.ndjson').read_bytes(), {'root': 'ntfy_archiver', 'file': 'state/messages.ndjson'})
        db = ARCHIVER / 'state/archive.sqlite3'
        wal = Path(str(db) + '-wal')
        if wal.exists() and wal.stat().st_size:
            self.parse_notes.append({'root': 'ntfy_archiver', 'file': 'state/archive.sqlite3', 'note': 'Active WAL: used the saved NDJSON instead of an immutable SQLite read.'})
        else:
            with sqlite3.connect(db.as_uri() + '?mode=ro&immutable=1', uri=True) as connection:
                connection.execute('PRAGMA query_only=ON')
                for url, data, received, origin in connection.execute('SELECT topic,event_json,received,origin FROM events'):
                    if topic_name(url):
                        self.add(json.loads(data), {'root': 'ntfy_archiver', 'file': 'state/archive.sqlite3',
                                                   'table': 'events', 'received_at': received, 'origin': origin})
        archive = LEADS / 'ntfy-archive.zip'
        with zipfile.ZipFile(archive) as z:
            for info in z.infolist():
                if info.filename.endswith(('.json', '.jsonl', '.body', '.txt')):
                    self.blob(z.read(info), {'root': 'hosted_probe_leads', 'file': 'ntfy-archive.zip', 'member': info.filename})


def main():
    collection = Collection()
    print('Merging saved Amap ntfy events and historical snapshots.', flush=True)
    collection.scan()
    collection.reconcile_observations()
    selected = list(collection.messages.values())
    print(f'Found {len(selected):,} distinct message versions/observations before redaction.', flush=True)
    expanded = []
    for item in selected:
        _, payloads = expand(item['core'].get('message') or '')
        expanded.append({**item['core'], 'decoded_payloads': payloads})
    redactor = Redactor()
    redactor.discover(strings(expanded))
    merged = {}
    for item, value in zip(selected, expanded, strict=True):
        safe = redactor.tree(redactor.tree(value))
        safe['published_at'] = iso_time(safe.get('unix_time'))
        safe['record_kind'] = 'ntfy_message' if safe.get('message_id') else 'ntfy_observation_without_event_id'
        safe['topic_url'] = 'https://ntfy.sh/' + safe['topic']
        safe['referenced_report_ids_in_export'] = sorted({rid.lower() for text in strings(safe) for rid in UUID.findall(text)} & collection.report_ids)
        rid = 'ntfy-' + hashlib.sha256(canonical(safe).encode()).hexdigest()[:24]
        row = merged.setdefault(rid, {**safe, 'record_id': rid, 'provenance': {}, 'observed_at': set(), 'expires_at': set()})
        for p in item['provenance']:
            p = json.loads(p)
            for k in ('file', 'member'):
                if k in p:
                    p[k] = '/'.join(redactor.clean(part) for part in p[k].split('/'))
            if 'origin' in p:
                p['origin'] = redactor.clean(p['origin'])
            row['provenance'][canonical(p)] = p
        row['observed_at'].update(item['observations'])
        row['expires_at'].update(filter(None, (iso_time(t) for t in item['expires'])))
    rows = []
    for row in merged.values():
        row['provenance'] = sorted(row['provenance'].values(), key=canonical)
        row['observed_at'] = sorted(row['observed_at'])
        row['expires_at'] = sorted(row['expires_at'])
        rows.append(row)
    rows.sort(key=lambda r: (r['published_at'] or '9999', r['topic'], r['message_id'] or '', r['record_id']))
    checks = audit(rows)
    assert not any(checks.values()), 'Redaction audit failed (counts only): ' + canonical(checks)
    assert all(r['topic'] in TOPICS for r in rows)
    assert len({r['record_id'] for r in rows}) == len(rows)
    topics = []
    for topic in TOPICS:
        subset = [r for r in rows if r['topic'] == topic]
        topics.append({'topic': topic, 'topic_url': 'https://ntfy.sh/' + topic,
                       'records': len(subset), 'message_records': sum(r['record_kind'] == 'ntfy_message' for r in subset),
                       'urlquery_report_ids_in_export': sorted(collection.topic_reports[topic]),
                       'relationship': 'The topic appears in saved evidence for these reports. Individual message authorship is not inferred.'})
    for name, values in (('ntfy-messages.jsonl', rows), ('ntfy-topics.jsonl', topics)):
        with (OUTPUT / name).open('w', encoding='utf-8') as f:
            for value in values:
                f.write(json.dumps(value, ensure_ascii=False, separators=(',', ':')) + '\n')
    summary = {'generated_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'records': len(rows),
               'message_records': sum(r['record_kind'] == 'ntfy_message' for r in rows),
               'observations_without_event_id': sum(r['record_kind'] != 'ntfy_message' for r in rows),
               'roots': {'findings': str(FINDINGS), 'ntfy_archiver': str(ARCHIVER), 'hosted_probe_leads': str(LEADS)},
               'files': dict(collection.stats), 'unreadable_files': collection.parse_notes, 'redaction_audit': checks,
               'scope_evidence': ['ntfy_archiver:topic-additions/20261006T042148Z-amap-only-correction.json',
                                  'ntfy_archiver:topic-additions/20261007T000006Z-amapmc-added.json'],
               'deduplication': 'Same topic, ID, timestamp, event type and message content merge across snapshots. Expiry and capture metadata are preserved separately. Changed content under the same ID remains a separate version.',
               'limitations': ['Saved local snapshots only. No live ntfy requests or attachments downloaded.',
                              'Messages without IDs or publication timestamps are explicitly labeled as observations.',
                              'Topic-level scan links do not identify which scan produced a specific message.',
                              'Secrets and encoded carriers are conservatively redacted with the same rules as the URLQuery export.']}
    (OUTPUT / 'ntfy-summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'records': len(rows), 'message_records': summary['message_records'],
                      'observations_without_event_id': summary['observations_without_event_id'],
                      'topics': {t['topic']: t['records'] for t in topics}, 'redaction_audit': checks}, indent=2))


if __name__ == '__main__':
    main()
