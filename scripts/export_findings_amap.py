#!/usr/bin/env python3
"""Export Amap URLQuery evidence from a local findings archive, without network I/O."""
from __future__ import annotations

import argparse
import collections
import csv
import datetime as dt
import gzip
import hashlib
import html
import json
import re
from pathlib import Path

from redaction import (
    AMAP, ASSIGN, BARE, BASE64_URL, HEX, MARK, OPAQUE, URL,
    Redactor, SensitiveInputs, expand, iso_utc, strings, variants,
)

UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.I)
REPORT_URL = re.compile(r"https?://(?:www\.)?urlquery\.net/report/(" + UUID.pattern + r")", re.I)
TARGET = re.compile(AMAP.pattern + r"|(?i:\bgaodemap\.com\b|\bgaode\.com\b|\bgaode\b)")
PROXY = re.compile(r"proxy|cors|allorigins|codetabs|jina\.ai|microlink|translate\.goog|translate\.google", re.I)
REQUEST = re.compile(PROXY.pattern + r"|amap|httpbin|httpbun|高德", re.I)
PAYLOAD_FIELD = re.compile(r"program|decoded|payload|html|script|content|body|layers", re.I)
SCAN_FIELDS = ('final_status', 'server_ip', 'server_asn', 'server_as', 'server_country', 'visibility',
               'alert_count', 'user_agent', 'referer', 'exit_node', 'tags', 'requests_total')


def target(text):
    lowered = text.lower()
    return any(s in lowered for s in ('amap', 'gaode', '高德')) and bool(TARGET.search(text))


def evidence_strings(value):
    """Exclude discovery queries, local paths and research annotations from selection."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            if re.search(r'source|file|path|quer(?:y|ies)|sql|params|note|match|reason|provenance', str(key), re.I):
                continue
            yield from evidence_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from evidence_strings(item)


def addr(value):
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get('addr') or value.get('url') or ''
    return ''


def scan_fields(capture):
    """Scan columns from a full capture. final_status is the last navigation to the final URL."""
    final, server, settings = capture.get('final') or {}, capture.get('ip') or {}, capture.get('settings') or {}
    http = capture['http'] if isinstance(capture.get('http'), list) else []
    http = [item for item in http if isinstance(item, dict)]
    codes = [str((item.get('response') or {}).get('status_code') or '') for item in http
             if item.get('is_navigation_request') and addr(item.get('url')) == addr(final.get('url'))]
    codes = [int(code) for code in codes if code.isdigit()]
    return {'final_status': codes[-1] if codes else None, 'server_ip': server.get('addr'),
            'server_asn': server.get('asn'), 'server_as': server.get('as'),
            'server_country': server.get('country_code'), 'visibility': settings.get('access'),
            'alert_count': sum(((capture.get('stats') or {}).get('alert_count') or {}).values()),
            'user_agent': settings.get('useragent'), 'referer': settings.get('referer') or None,
            'exit_node': settings.get('exit_node'), 'tags': capture.get('tags') or [], 'requests_total': len(http)}


def report_id(value):
    if not isinstance(value, str):
        return None
    match = UUID.fullmatch(value) or REPORT_URL.search(value)
    if match:
        return match.group(1).lower() if match.lastindex else match.group().lower()


def records(value, context=False, inherited=None):
    """Recognize report objects, SQL row exports, UUID maps, and per-report files."""
    if isinstance(value, list):
        for item in value:
            yield from records(item, context, inherited)
    elif isinstance(value, dict):
        scanner = str(value.get('scanner', value.get('service', ''))).lower()
        if scanner == 'urlscan' or ('task' in value and 'page' in value and 'lists' in value):
            return
        direct = REPORT_URL.search(str(value.get('report_url', '')))
        rid = report_id(value.get('report_id')) or report_id(value.get('report'))
        raw = 'http' in value and 'submit' in value
        if direct:
            rid = direct[1].lower()
        if not rid and (context or raw or scanner == 'urlquery'):
            rid = report_id(value.get('id'))
        if rid and (context or raw or direct or 'report_id' in value or scanner == 'urlquery'):
            yield rid, value
            return
        if inherited and any(k in value for k in ('submit', 'submitted_url', 'final', 'http')):
            yield inherited, value
            return
        for key, item in value.items():
            keyed = report_id(key)
            if keyed and isinstance(item, dict):
                yield keyed, item
            elif isinstance(item, (dict, list)):
                yield from records(item, context, inherited)


class Evidence:
    def __init__(self):
        self.reports = {}
        self.expansions = {}
        self.file_counts = collections.Counter()
        self.errors = []
        self.unique_files = {}

    def get(self, rid):
        return self.reports.setdefault(rid, {
            'report_id': rid, 'report_url': 'https://urlquery.net/report/' + rid,
            'dates': set(), 'submitted_urls': set(), 'final_urls': set(), 'titles': set(),
            'evidence_urls': set(), 'source_files': set(), 'decoded': set(),
            'match_basis': set(), 'requests': {}, 'raw_capture_available': False,
            **dict.fromkeys(SCAN_FIELDS),
        })

    def unpack(self, text):
        if text not in self.expansions:
            if len(self.expansions) > 25000:
                self.expansions.clear()
            self.expansions[text] = expand(text)
        return self.expansions[text]

    def add(self, rid, obj, source):
        r = self.get(rid)
        r['source_files'].add(source)
        raw = 'http' in obj and 'submit' in obj
        r['raw_capture_available'] |= raw
        if raw:
            # A report archived more than once keeps the columns of its fullest capture.
            fields = scan_fields(obj)
            if fields['requests_total'] >= (r['requests_total'] or 0):
                r.update(fields)
        for key in ('date', 'reported', 'reported_at', 'scanned_at', 'listed', 'report_time_utc'):
            v = obj.get(key)
            if isinstance(v, str) and re.match(r'\d{4}-\d\d-\d\d', v):
                r['dates'].add(v)
        submit = obj.get('submit', {})
        final = obj.get('final', {})
        is_request = 'ordinal' in obj or ('method' in obj and ('status' in obj or 'status_code' in obj))
        for v in (obj.get('submitted_url'), obj.get('submitted'), submit.get('url') if isinstance(submit, dict) else None,
                  obj.get('url') if not raw and not is_request else None):
            v = addr(v)
            if v.startswith(('http://', 'https://')):
                r['submitted_urls'].add(v)
        for v in (obj.get('final_url'), final.get('url') if isinstance(final, dict) else None):
            v = addr(v)
            if v.startswith(('http://', 'https://')):
                r['final_urls'].add(v)
        for v in (obj.get('final_title'), obj.get('title'), final.get('title') if isinstance(final, dict) else None):
            if isinstance(v, str) and v:
                r['titles'].add(v)
        # Extract URLs from all report evidence, including request, DOM and decoded inventories.
        for text in evidence_strings(obj):
            if target(text):
                r['match_basis'].add('amap_reference_in_saved_report_evidence')
            if not ('http' in text or '/base64/' in text or target(text)):
                continue
            normalized = html.unescape(text.replace(r'\/', '/'))
            urls = URL.findall(normalized)
            if normalized.startswith(('http://', 'https://')) and not any(c in normalized for c in '\n\r<>"'):
                urls.append(normalized)
            for url in urls:
                # Report links identify provenance, not the scanned destination.
                if REPORT_URL.fullmatch(url.rstrip('/')):
                    continue
                if not target(url) and '/base64/' not in url and not PROXY.search(url) and not OPAQUE.search(url):
                    continue
                r['evidence_urls'].add(url)
                expanded, decoded = self.unpack(url)
                r['decoded'].update(decoded)
                if any(target(v) for v in expanded):
                    r['match_basis'].add('amap_in_url_or_decoded_carrier')
        for i, req in enumerate(obj.get('http', []) if isinstance(obj.get('http'), list) else []):
            if not isinstance(req, dict):
                continue
            url = addr(req.get('url'))
            if not url:
                continue
            expanded, _ = self.unpack(url)
            if not any(target(v) for v in expanded) and not REQUEST.search(url) and '/base64/' not in url:
                continue
            request, response = req.get('request') or {}, req.get('response') or {}
            item = {'ordinal': i, 'url': url, 'method': request.get('method'),
                    'status_code': response.get('status_code'), 'requested_at': req.get('date'),
                    'ip': (req.get('ip') or {}).get('addr'), 'resource_type': req.get('resource_type'),
                    'navigation': bool(req.get('is_navigation_request')), 'initiator': req.get('requested_by') or None}
            r['requests'][json.dumps(item, sort_keys=True)] = item

    def load(self, root):
        paths = sorted(p for p in root.rglob('*') if p.is_file() and
                       (p.suffix in ('.json', '.jsonl') or p.name.endswith(('.json.gz', '.jsonl.gz'))))
        print(f'Inspecting {len(paths):,} structured evidence files.', flush=True)
        for i, path in enumerate(paths, 1):
            rel = path.relative_to(root).as_posix()
            if 'node_modules/' in rel or '/.git/' in rel:
                continue
            self.file_counts['structured_files_considered'] += 1
            data = path.read_bytes()
            digest = hashlib.sha256(data).digest()
            if digest in self.unique_files:
                for rid in self.unique_files[digest]:
                    self.get(rid)['source_files'].add(rel)
                self.file_counts['duplicate_files'] += 1
                continue
            ids = set()
            try:
                if path.suffix == '.gz':
                    data = gzip.decompress(data)
                text = data.decode('utf-8-sig')
                context = ('urlquery' in rel.lower() or 'amap' in rel.lower() or 'urlquery' in text[:3000].lower()) and 'urlscan' not in rel.lower()
                inherited = report_id(path.name.split('.')[0]) if context else None
                objs = (json.loads(line) for line in text.splitlines() if line.strip()) if '.jsonl' in path.name else [json.loads(text)]
                for obj in objs:
                    for rid, record in records(obj, context, inherited):
                        self.add(rid, record, rel)
                        ids.add(rid)
                self.file_counts['parsed_files'] += 1
            except (ValueError, UnicodeError, OSError, RecursionError) as exc:
                self.errors.append({'source_file': rel, 'error_type': type(exc).__name__})
            self.unique_files[digest] = ids
            if i % 1000 == 0:
                print(f'Inspected {i:,}/{len(paths):,} files; {len(self.reports):,} report IDs.', flush=True)
        self.load_additional(root)
        return [r for r in self.reports.values() if r['match_basis']]

    def load_additional(self, root):
        """Reconcile CSV inventories and report rows in saved HTML listings."""
        before = {rid for rid, r in self.reports.items() if r['match_basis']}
        for path in sorted(root.rglob('*.csv')):
            rel = path.relative_to(root).as_posix()
            with path.open(encoding='utf-8-sig', errors='replace', newline='') as f:
                reader = csv.DictReader(f)
                if not any(k in (reader.fieldnames or []) for k in ('report_id', 'report_url')):
                    continue
                self.file_counts['csv_inventories'] += 1
                for obj in reader:
                    rid = report_id(obj.get('report_id')) or report_id(obj.get('report_url'))
                    if not rid:
                        continue
                    self.add(rid, obj, rel)
                    # Saved feature tables identify Amap API calls even when the URL uses an IP.
                    if 'amap' in rel.lower() and any(obj.get(k) in ('1', 'true', 'True') for k in ('api_in_url', 'api_in_content_only')):
                        self.get(rid)['match_basis'].add('amap_api_classification_in_saved_inventory')
        for path in sorted(root.rglob('*.html')):
            text = path.read_text(encoding='utf-8', errors='replace')
            if '/report/' not in text:
                continue
            rel = path.relative_to(root).as_posix()
            self.file_counts['html_files_with_report_links'] += 1
            for row in re.findall(r'<tr\b.*?</tr>', text, re.I | re.S):
                ids = set(re.findall(r'/report/(' + UUID.pattern + r')', row, re.I))
                if len(ids) != 1:
                    continue
                rid = next(iter(ids)).lower()
                plain = html.unescape(re.sub(r'<[^>]*>', '\n', row))
                obj = {'report_id': rid, 'saved_listing_text': plain}
                urls = URL.findall(plain)
                if urls:
                    obj['submitted_url'] = urls[0]
                date = re.search(r'\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?', plain)
                if date:
                    obj['date'] = date.group()
                self.add(rid, obj, rel)
        new_ids = {rid for rid, r in self.reports.items() if r['match_basis']} - before
        self.file_counts['reports_added_from_csv_or_html'] += len(new_ids)
        # Retrieve captures for reports whose relationship was first established by an inventory.
        for path in root.rglob('*'):
            rid = report_id(path.name.split('.')[0])
            if rid not in new_ids or not path.is_file() or not path.name.endswith(('.json', '.json.gz')):
                continue
            try:
                data = gzip.decompress(path.read_bytes()) if path.suffix == '.gz' else path.read_bytes()
                obj = json.loads(data)
                if isinstance(obj, dict):
                    self.add(rid, obj, path.relative_to(root).as_posix())
            except (ValueError, UnicodeError, OSError):
                pass

    def resume(self, directory):
        summary = json.loads((directory / 'summary.json').read_text())
        payloads = {p['payload_id']: p['decoded_content_redacted'] for p in map(json.loads, (directory / 'payloads.jsonl').open())}
        self.file_counts.update(summary['file_counts'])
        self.errors = summary['parse_errors']
        for line in (directory / 'reports.jsonl').open():
            row = json.loads(line)
            r = self.get(row['report_id'])
            for key in ('dates', 'submitted_urls', 'final_urls', 'titles', 'evidence_urls', 'source_files', 'match_basis'):
                r[key].update(row[key])
            r['raw_capture_available'] = row['raw_capture_available']
            r.update({key: row[key] for key in SCAN_FIELDS})
            r['decoded'].update(payloads[pid] for pid in row['decoded_payload_ids'])
            r['requests'].update({json.dumps(req, sort_keys=True): req for req in row['requests']})


def earliest(dates):
    """Earliest saved time. Minute-only listing dates count only when nothing finer exists."""
    precise = [d for d in dates if len(d) > len('2026-01-01 00:00')]
    return min(filter(None, map(iso_utc, precise or dates)), default=None)


def serializable(r):
    out = {k: sorted(v) if isinstance(v, set) else v for k, v in r.items() if k not in ('decoded', 'requests')}
    out['requests'] = list(r['requests'].values())
    out['decoded_payloads'] = sorted(r['decoded'])
    return out


def audit(rows):
    issues = collections.Counter({'sensitive_assignments': 0, 'hex32_values': 0,
                                  'encoded_carriers': 0, 'sensitive_inputs': 0})
    for text in strings(rows):
        for exposed in variants(text):
            for pattern in (ASSIGN, BARE):
                for m in pattern.finditer(exposed):
                    if m['value'] != MARK:
                        issues['sensitive_assignments'] += 1
            issues['hex32_values'] += len(HEX.findall(exposed))
            issues['encoded_carriers'] += sum(not m[2].startswith('[REDACTED') for m in BASE64_URL.finditer(exposed))
        probe = SensitiveInputs()
        probe.feed(text)
        issues['sensitive_inputs'] += len(probe.values - {MARK})
    return dict(issues)


def refresh_provenance(source, directory):
    """Recover exact relative paths from report-ID references, without carrying raw content out."""
    rows = [json.loads(line) for line in (directory / 'reports.jsonl').open()]
    references = {r['report_id']: set() for r in rows}
    ids = set(references)
    # A literal dash lets the regex engine skip long encoded payloads efficiently.
    uuid_tail = re.compile(r'-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.I)
    files = 0
    for path in source.rglob('*'):
        if not path.is_file() or path.suffix not in ('.json', '.jsonl', '.gz', '.html', '.csv', '.txt', '.md'):
            continue
        if path.suffix == '.gz' and not path.name.endswith(('.json.gz', '.jsonl.gz')):
            continue
        try:
            data = path.read_bytes()
            if path.suffix == '.gz':
                data = gzip.decompress(data)
            text = data.decode('utf-8', errors='replace')
        except (OSError, ValueError):
            continue
        files += 1
        found = ({text[m.start() - 8:m.end()].lower() for m in uuid_tail.finditer(text) if m.start() >= 8}
                 | {v.lower() for v in UUID.findall(path.name)}) & ids
        rel = path.relative_to(source).as_posix()
        for rid in found:
            references[rid].add(rel)
    redactor = Redactor()
    redactor.discover(path for paths in references.values() for path in paths)
    for row in rows:
        paths = references[row['report_id']]
        if paths:
            row['source_files'] = sorted({'/'.join(redactor.clean(part) for part in path.split('/')) for path in paths})
    checks = audit(rows)
    assert not any(checks.values()), 'Provenance redaction audit failed: ' + json.dumps(checks)
    temporary = directory / 'reports.jsonl.tmp'
    with temporary.open('w', encoding='utf-8') as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, separators=(',', ':')) + '\n')
    temporary.replace(directory / 'reports.jsonl')
    summary = json.loads((directory / 'summary.json').read_text())
    summary['provenance'] = 'Exact relative paths of saved files referencing each report ID, including filenames containing that ID.'
    summary['provenance_files_inspected'] = files
    summary['redaction_audit'] = checks
    (directory / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'reports': len(rows), 'provenance_files_inspected': files, 'redaction_audit': checks}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path('/Users/concurrent/Projects/oai-scraping-test/findings'))
    parser.add_argument('--output', type=Path, default=Path('data/amap-findings'))
    parser.add_argument('--supplement-existing', action='store_true', help='Reconcile existing sanitized output against CSV/HTML inventories.')
    parser.add_argument('--refresh-provenance', action='store_true', help='Refresh exact source-file references in an existing export.')
    args = parser.parse_args()
    if args.refresh_provenance:
        refresh_provenance(args.source, args.output)
        return
    evidence = Evidence()
    if args.supplement_existing:
        evidence.resume(args.output)
        evidence.load_additional(args.source)
        selected = [r for r in evidence.reports.values() if r['match_basis']]
    else:
        selected = evidence.load(args.source)
    print(f'Selected {len(selected):,} Amap-related report IDs. Redacting in memory.', flush=True)
    records_out = [serializable(r) for r in selected]
    redactor = Redactor()
    redactor.discover(strings(records_out))
    safe, catalogue = [], {}
    for i, row in enumerate(records_out, 1):
        source_files = row['source_files']
        row = redactor.tree(row)
        # A second contextual pass catches assignments exposed by earlier substitutions.
        row = redactor.tree(row)
        # Preserve directory separators: a long local path is not an opaque credential.
        row['source_files'] = sorted({'/'.join(redactor.clean(part) for part in source.split('/')) for source in source_files})
        row['decoded_payload_ids'] = []
        for content in dict.fromkeys(row.pop('decoded_payloads')):
            pid = 'payload-' + hashlib.sha256(content.encode()).hexdigest()[:20]
            row['decoded_payload_ids'].append(pid)
            entry = catalogue.setdefault(pid, {
                'payload_id': pid, 'decoded_content_redacted': content,
                'content_type': 'text/html' if re.search(r'<(?:!doctype|html|script|body|meta)\b', content, re.I) else 'text/plain',
                'referenced_urls': sorted(set(URL.findall(content))), 'report_ids': []})
            entry['report_ids'].append(row['report_id'])
        row['scanned_at'] = earliest(row['dates'])
        proxy_urls = [url for url in row['evidence_urls'] if PROXY.search(url)]
        row['proxy_urls'] = proxy_urls
        row['has_proxy_evidence'] = bool(proxy_urls)
        row['has_base64_carrier'] = any('/base64/' in url for url in row['evidence_urls'])
        safe.append(row)
        if i % 500 == 0:
            print(f'Redacted {i:,}/{len(records_out):,} reports.', flush=True)
    safe.sort(key=lambda r: (r['scanned_at'] or '9999', r['report_id']))
    checks = audit([safe, list(catalogue.values())])
    if any(checks.values()):
        raise RuntimeError('Redaction audit failed (counts only): ' + json.dumps(checks))
    assert len({r['report_id'] for r in safe}) == len(safe)
    args.output.mkdir(parents=True, exist_ok=True)
    output = args.output / 'reports.jsonl'
    with output.open('w', encoding='utf-8') as f:
        for row in safe:
            f.write(json.dumps(row, ensure_ascii=False, separators=(',', ':')) + '\n')
    with (args.output / 'payloads.jsonl').open('w', encoding='utf-8') as f:
        for pid in sorted(catalogue):
            f.write(json.dumps(catalogue[pid], ensure_ascii=False, separators=(',', ':')) + '\n')
    summary = {
        'schema_version': '1.0', 'generated_at': dt.datetime.now(dt.timezone.utc).isoformat(),
        'source_directory': str(args.source), 'reports': len(safe),
        'reports_with_raw_captures': sum(r['raw_capture_available'] for r in safe),
        'reports_with_decoded_payloads': sum(bool(r['decoded_payload_ids']) for r in safe),
        'reports_with_proxy_evidence': sum(r['has_proxy_evidence'] for r in safe),
        'unique_decoded_payloads': len(catalogue), 'file_counts': dict(evidence.file_counts),
        'parse_errors': evidence.errors, 'redaction_audit': checks,
        'selection': 'Amap/amap.com/Gaode references in saved report evidence, recorded URLs, and recursively decoded base64 carriers. Proxy and redirect wrappers included.',
        'limitations': [
            'Coverage is the local findings archive, including saved listings without full captures. No live URLQuery fetches.',
            'Structured JSON/JSONL, gzip JSON, CSV report inventories and report rows in saved HTML listings are inspected. Standalone prose, images and SQLite databases are not scanned.',
            'Base64 decoding is local, UTF-8 only, at most six nested levels and four million encoded characters per value.',
            'Payloads include httpbin-compatible /base64/ carriers and nested base64/data-URI carriers. Original encoded carriers are suppressed to prevent secret recovery.',
            'Proxy evidence indicates a known proxy service or proxy/cors URL marker within an Amap-related report; it does not prove every proxy URL targets Amap.',
            'Secrets, 32-character hex values, and long opaque values are conservatively redacted. Sanitized evidence may no longer execute.',
        ],
    }
    (args.output / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k not in ('parse_errors', 'limitations')}, indent=2))


if __name__ == '__main__':
    main()
