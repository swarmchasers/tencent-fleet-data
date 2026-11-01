#!/usr/bin/env python3
"""Shared redaction and carrier decoding for the local exports."""
from __future__ import annotations
import base64
import datetime as dt
import html
from html.parser import HTMLParser
import json
import re
from urllib.parse import unquote, quote

AMAP = re.compile(r'(?i)(?<![\w-])(?:[\w-]+\.)*amap\.com\b|\bAMap\b|_AMapSecurityConfig|高德')
SECRET_NAME = r'(?:[\w$.-]*(?:api[_-]?key|access[_-]?key|secret|security[_-]?(?:js[_-]?)?code|jscode|token|password|passwd|authorization|credential|signature)[\w$.-]*|key|sig|cookie|session(?:id)?)'
ASSIGN = re.compile(r'''(?ix)(?P<prefix>["']?\b(?P<name>''' + SECRET_NAME + r''')\b["']?\s*[:=]\s*)(?P<quote>["'`])(?P<value>.*?)(?P=quote)''', re.S)
BARE = re.compile(r'(?i)(?P<prefix>\b'+SECRET_NAME+r'\b\s*[:=]\s*)(?P<value>[^\s&;,<>"\'`{}\[\]()]+)')
HEX = re.compile(r'(?i)(?<![a-z0-9])[a-f0-9]{32}(?![a-z0-9])')
BASE64_URL = re.compile(r'(?i)(/base64/)([^\s<>"\'`?#]+)')
DATA = re.compile(r'(?i)(data:[^\s,;"\'<>]*;base64,)([a-zA-Z0-9+/=_%-]+)')
OPAQUE = re.compile(r'(?<![\w])(?:[A-Za-z0-9+/_-]|%[0-9A-Fa-f]{2}){80,}={0,2}')
URL = re.compile(r'https?://[^\s<>"\'`\\]+', re.I)
MARK = '[REDACTED]'


def unescape_once(text):
    text = html.unescape(unquote(text))
    text = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m[1], 16)), text)
    text = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m[1], 16)), text)
    return text.replace(r'\/', '/').replace(r'\"', '"').replace(r"\'", "'")


def variants(text):
    """Expose percent, HTML, JSON/JS escape layers before checking or redacting."""
    seen = {text}
    for _ in range(4):
        changed = {unescape_once(s) for s in seen}
        if changed <= seen:
            break
        seen |= changed
    return seen


def decode64(value):
    value = unquote(value).strip()
    if len(value) > 4_000_000:
        return None
    try:
        raw = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
        text = raw.decode('utf-8')
        if text and sum(c.isprintable() or c in '\n\r\t' for c in text) / len(text) > .95:
            return text
    except (ValueError, UnicodeError):
        pass
    return None


def expand(text):
    """Recursively inspect carrier URLs without making any HTTP requests."""
    seen, pending, payloads = set(), [(text, 0)], []
    while pending:
        value, depth = pending.pop()
        if value in seen or depth > 6:
            continue
        seen.add(value)
        for v in variants(value):
            if v not in seen:
                pending.append((v, depth + 1))
            encoded = [m[2] for m in BASE64_URL.finditer(v)]
            encoded += [m[2] for m in DATA.finditer(v)]
            encoded += [m.group() for m in OPAQUE.finditer(v)]
            for token in encoded:
                decoded = decode64(token)
                if decoded is not None and decoded not in seen:
                    payloads.append(decoded)
                    pending.append((decoded, depth + 1))
    return seen, list(dict.fromkeys(payloads))


class SensitiveInputs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.values = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'input' and (attrs.get('type') == 'password' or
                re.fullmatch(SECRET_NAME, attrs.get('name', ''), re.I)):
            if attrs.get('value'):
                self.values.add(attrs['value'])


class Redactor:
    """Remove credentials and carriers while retaining source escaping and code layout."""
    def __init__(self):
        self.secrets = set()
        self.secret_regex = None

    def discover(self, texts):
        for text in texts:
            for v in variants(text):
                inputs = SensitiveInputs()
                inputs.feed(v)
                self.secrets.update(inputs.values)
                for pattern in (ASSIGN, BARE):
                    for m in pattern.finditer(v):
                        secret = m['value']
                        if secret and secret not in (MARK, 'undefined', 'null', 'true', 'false'):
                            self.secrets.add(secret)
                self.secrets.update(HEX.findall(v))
        forms = set()
        for s in self.secrets:
            forms |= {s, quote(s, safe=''), html.escape(s), json.dumps(s)[1:-1]}
        # Bare code expressions can resemble assignments. Only propagate high-entropy values.
        forms = [s for s in forms if len(s) >= 12 and not re.search(r'\s', s)
                 and re.search(r'\d|[^a-zA-Z]', s) and not s.startswith('[REDACTED')]
        # Longest first prevents replacing a short value inside another secret.
        forms.sort(key=len, reverse=True)
        self.secret_regex = re.compile('|'.join(re.escape(s) for s in forms)) if forms else None

    def clean(self, text):
        # Normalize encoding layers before matching short values and encoded key names.
        for _ in range(4):
            normalized = unescape_once(text)
            if normalized == text:
                break
            text = normalized
        text = BASE64_URL.sub(lambda m: m[1] + '[REDACTED_BASE64_PAYLOAD]', text)
        text = DATA.sub(lambda m: m[1] + '[REDACTED_BASE64_PAYLOAD]', text)
        text = ASSIGN.sub(lambda m: m['prefix'] + m['quote'] + MARK + m['quote'], text)
        text = BARE.sub(lambda m: m['prefix'] + MARK, text)
        text = HEX.sub(MARK, text)
        if self.secret_regex:
            text = self.secret_regex.sub(MARK, text)
        text = OPAQUE.sub('[REDACTED_OPAQUE_VALUE]', text)
        text = re.sub(r'(?i)(https?://)[^/\s@]+@', r'\1[REDACTED]@', text)
        def clean_input(match):
            tag = match.group()
            probe = SensitiveInputs()
            probe.feed(tag)
            if probe.values:
                return re.sub(r'''(?i)(\bvalue\s*=\s*)(?:(["'])(.*?)\2|([^\s>]+))''', lambda m: m[1] + '"[REDACTED]"', tag)
            return tag
        return re.sub(r'<input\b[^>]*>', clean_input, text, flags=re.I)

    def tree(self, value):
        if isinstance(value, str):
            return self.clean(value)
        if isinstance(value, dict):
            return {str(k): MARK if re.fullmatch(SECRET_NAME, str(k), re.I) else self.tree(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.tree(v) for v in value]
        if value is None or isinstance(value, (int, float, bool)):
            return value
        return str(value)


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from strings(v)


def iso_utc(value, timespec='seconds'):
    """Normalize a saved date to ISO 8601 UTC. Values without an offset are already UTC."""
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.strip().replace('Z', '+00:00'))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc).isoformat(timespec=timespec)
