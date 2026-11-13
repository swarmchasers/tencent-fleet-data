# Amap URLQuery, ntfy and webhook data

- `reports.jsonl`: one record per URLQuery report, with scan details, relevant requests and decoded payload IDs.
- `payloads.jsonl`: the decoded payload text, deduplicated after redaction, with content type, referenced URLs and report IDs.
- `summary.json`: coverage, counts, selection rules, parse failures and redaction audit.
- `ntfy-messages.jsonl`: 377 deduplicated messages from the two confirmed Amap ntfy topics, with original IDs, publication times, redacted content and capture provenance.
- `ntfy-topics.jsonl`: topic counts and links to URLQuery reports in this export.
- `ntfy-summary.json`: ntfy source roots, scope evidence, deduplication rules and redaction audit.
- `webhook-requests.jsonl`: 627 archived webhook requests from 22 Amap-linked mailboxes, with redacted bodies, query fields and headers, plus source references.
- `webhook-configurations.jsonl`: 31 saved mailbox configuration versions, including redacted response content and decoded payloads.
- `webhook-mailboxes.jsonl`: mailbox scope, capture counts and links to existing URLQuery reports. Mailboxes without saved captures remain listed with zero requests.
- `ntfy-attachments.jsonl`: the cached text attachment linked to its original ntfy message, with verified source size/checksum and redacted content inline.
- `webhook-attachments-summary.json`: source roots, selection, coverage and redaction audits for the webhook and attachment additions.
- `mailbox-conversations.jsonl`: 27 threads between Amap fleet agents and the mailbox.termina.digital honeypot inbox (47 agent messages, 31 replies, 595 inbox checks), one record per inbox, with exact original text and English translations.

Credentials and security codes are redacted.
