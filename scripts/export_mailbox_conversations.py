#!/usr/bin/env python3
"""Export the Amap fleet mailbox conversations from the reviewed .docx record to JSONL."""
from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET
import zipfile

W = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'
DEFAULT_SOURCE = Path.home() / 'Downloads' / 'fleet-mailbox-conversations.docx'
OUTPUT = Path(__file__).resolve().parent.parent / 'data' / 'amap-findings' / 'mailbox-conversations.jsonl'
YEAR = 2026  # The record gives day and month only; message bodies date the exchange to October 2026.
MONTHS = {'Oct': 10}
INBOX = re.compile(r'Inbox ([0-9a-f]{16})')
SECTION = re.compile(r'(\d+)\. (.+)')
PLACE = re.compile(r'(.+?) (B[0-9A-Z]{9}) \((.+)\)')
TIME = re.compile(r'(\d{1,2}) ([A-Z][a-z]{2}) (\d{2}:\d{2}:\d{2})')
COUNTED = re.compile(r'(.+?) \((\d+) msg\)(?:, |$)')
CHECKS = re.compile(r'(\d+)(?: \(first (.+?), last (.+?)\))?( \(all before our first reply\))?')
MESSAGES = re.compile(r'(\d+) from the agent, (\d+) from us')
ENGLISH_ORIGINAL = '(original in English)'


def text(element):
    out = []
    for el in element.iter():
        if el.tag == W + 't':
            out.append(el.text or '')
        elif el.tag == W + 'tab':
            out.append('\t')
        elif el.tag in (W + 'br', W + 'cr'):
            out.append('\n')
    return ''.join(out)


def cell_text(cell):
    return '\n'.join(text(p) for p in cell.iter(W + 'p'))


def monospace(cell):
    return any(f.get(W + 'ascii') == 'Menlo' for f in cell.iter(W + 'rFonts'))


def timestamp(value):
    m = TIME.fullmatch(value.strip())
    if not m:
        raise ValueError(f'unrecognized time: {value!r}')
    day, month, clock = m.groups()
    return f'{YEAR}-{MONTHS[month]:02d}-{int(day):02d}T{clock}+00:00'


def counted(value, key):
    return [{key: m[1], 'messages': int(m[2])} for m in COUNTED.finditer(value)]


def place(value):
    if value in ('no place named', '-'):
        return None
    m = PLACE.fullmatch(value)
    if not m:
        raise ValueError(f'unrecognized place: {value!r}')
    return {'name_zh': m[1], 'poi_id': m[2], 'name_en': m[3], 'amap_url': 'https://www.amap.com/place/' + m[2]}


def inbox_checks(value):
    m = CHECKS.fullmatch(value)
    if not m:
        raise ValueError(f'unrecognized inbox checks: {value!r}')
    return {'count': int(m[1]), 'first_at': m[2] and timestamp(m[2]), 'last_at': m[3] and timestamp(m[3]),
            'all_before_first_reply': bool(m[4])}


def rows(table):
    return [r.findall(W + 'tc') for r in table.findall(W + 'tr')]


def parse(path):
    body = ET.fromstring(zipfile.ZipFile(path).read('word/document.xml')).find(W + 'body')
    threads, section, current = [], None, None
    appendix = None
    for child in body:
        if child.tag == W + 'p':
            line = text(child).strip()
            if m := SECTION.fullmatch(line):
                section = {'number': int(m[1]), 'title': m[2]}
            elif line == 'Appendix: all threads':
                section = 'appendix'
            elif m := INBOX.fullmatch(line):
                current = {'inbox_id': m[1], 'meta': {}}
                threads.append((section, current))
            elif current and ': ' in line:
                key, value = line.split(': ', 1)
                current['meta'][key] = value
        elif child.tag == W + 'tbl':
            table = rows(child)
            header = [cell_text(c) for c in table[0]]
            if section == 'appendix':
                appendix = {cell_text(r[0]): dict(zip(header, map(cell_text, r))) for r in table[1:]}
            else:
                assert header == ['Time (UTC)', 'From', 'Original', 'English'], header
                current['rows'] = table[1:]
    return threads, appendix


def build(path):
    threads, appendix = parse(path)
    records = []
    for section, t in threads:
        meta, summary = t['meta'], appendix[t['inbox_id']]
        agent_count, reply_count = map(int, MESSAGES.fullmatch(meta['Messages']).groups())
        sender_ips = counted(meta['Sender IP(s)'], 'ip')
        user_agents = counted(meta['User agent(s)'], 'user_agent')
        messages = []
        for i, (time, sender, original, english) in enumerate(t['rows']):
            english_text = cell_text(english)
            role, _, ip = cell_text(sender).partition('\n')
            role = {'Agent': 'agent', 'Us': 'mailbox'}[role]
            # The record prints an IP beside each message only in multi-IP threads; otherwise the thread has one.
            if role == 'agent' and not ip and len(sender_ips) == 1:
                ip = sender_ips[0]['ip']
            messages.append({
                'index': i,
                'sent_at': timestamp(cell_text(time)),
                'from': role,
                'sender_ip': ip or None,
                'user_agent': user_agents[0]['user_agent'] if role == 'agent' and len(user_agents) == 1 else None,
                'original': cell_text(original),
                'original_in_english': english_text == ENGLISH_ORIGINAL,
                'english': None if english_text == ENGLISH_ORIGINAL else english_text,
                'contains_raw_json': monospace(original),
            })
        record = {
            'record_kind': 'mailbox_thread',
            'inbox_id': t['inbox_id'],
            'inbox_url': 'https://mailbox.termina.digital/inbox/' + t['inbox_id'],
            'section': section['number'],
            'section_title': section['title'],
            'place': place(meta['Place asked about']),
            'first_message_at': timestamp(meta['First message']),
            'last_message_at': timestamp(summary['Last msg']),
            'agent_message_count': agent_count,
            'reply_count': reply_count,
            'sender_ips': sender_ips,
            'user_agents': user_agents,
            'inbox_checks': inbox_checks(meta['Inbox checks']),
            'self_description_highlights': summary['Self-description highlights'],
            'messages': messages,
        }
        check(record, summary)
        records.append(record)
    total = appendix['Total']
    assert len(records) == int(total['Place'].split()[0])
    assert sum(r['agent_message_count'] for r in records) == int(total['Agent msgs'])
    assert sum(r['reply_count'] for r in records) == int(total['Our replies'])
    assert sum(r['inbox_checks']['count'] for r in records) == int(total['Inbox checks'])
    return records


def check(record, summary):
    """Cross-check each thread's header, table and appendix row against one another."""
    messages = record['messages']
    assert sum(m['from'] == 'agent' for m in messages) == record['agent_message_count'] == int(summary['Agent msgs'])
    assert sum(m['from'] == 'mailbox' for m in messages) == record['reply_count'] == int(summary['Our replies'])
    assert sum(x['messages'] for x in record['sender_ips']) == record['agent_message_count']
    ips = collections.Counter(m['sender_ip'] for m in messages if m['from'] == 'agent')
    assert ips == {x['ip']: x['messages'] for x in record['sender_ips']}, ips
    assert sum(x['messages'] for x in record['user_agents']) == record['agent_message_count']
    assert record['inbox_checks']['count'] == int(summary['Inbox checks'])
    assert record['section'] == int(summary['Sect.'])
    assert record['first_message_at'] == timestamp(summary['First msg'])
    agent_times = [m['sent_at'] for m in messages if m['from'] == 'agent']
    assert (min(agent_times), max(agent_times)) == (record['first_message_at'], record['last_message_at'])
    assert record['place'] == place(summary['Place'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', nargs='?', type=Path, default=DEFAULT_SOURCE)
    parser.add_argument('--output', type=Path, default=OUTPUT)
    args = parser.parse_args()
    records = build(args.source)
    with args.output.open('w', encoding='utf-8') as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False, separators=(',', ':')) + '\n')
    print(json.dumps({'threads': len(records),
                      'agent_messages': sum(r['agent_message_count'] for r in records),
                      'replies': sum(r['reply_count'] for r in records),
                      'inbox_checks': sum(r['inbox_checks']['count'] for r in records)}, indent=2))


if __name__ == '__main__':
    main()
