# Amap URLQuery, ntfy and webhook data

Source: `~/Projects/oai-scraping-test/findings`.

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

Webhook scope comes from saved Amap archiver configuration decisions and mailbox references in the existing Amap report collection. Explicitly classified cancer collectors are excluded. Requests and configurations merge across the local archiver and historical findings/captures; changed objects retain separate versions. A mailbox-level relationship does not attribute every request to a particular URLQuery scan. Public mailbox and request IDs remain available for joins, while credentials and security codes are redacted. The addition includes all 306 applicable request IDs in the local archiver plus historical captures.

Attachment content is exported from the cached local file after checking its size and checksum against saved metadata. Original attachment bytes are not copied into the export. The attachment JSONL links back through `ntfy_record_ids` and `ntfy_message_ids`. These additions do not fetch remote mailbox history, S3 objects or attachments.

The ntfy topics are `shmq-1791251472-a7x` and `amapmc1791285782`. Their Amap relationship is documented in the archiver's saved topic-addition records. Messages merge across the findings archive, historical captures under `chinese-swarm/hosted-probe-leads`, and the local `chinese-swarm/ntfy-archiver` store. Other targets' topics are excluded. No live messages or attachment binaries were fetched. `decoded_payloads` is empty on every ntfy message because none carries decodable base64 text; the opaque values in them decode only to binary.

The ntfy export preserves content versions under reused IDs. Watcher records using `msg_id` are normalized to the original ID. A receipt without an ID is merged only when its topic, publication time and available content identify exactly one retained event. Capture times and expiry observations remain separate from publication time. Topic-level URLQuery links show that a report references a channel; they do not attribute a specific message to a particular scan.

The mailbox conversations come from the reviewed record `fleet-mailbox-conversations.docx`, not from the archiver stores. Each thread has its place (Chinese name, Amap POI ID and English name), sender IP and user-agent counts, inbox-check counts, the appendix's self-description highlights, and `messages` in time order. `original` is the exact sent text. `english` contains the record's translation, or `null` when `original_in_english` is true. `contains_raw_json` marks messages with untranslated raw JSON. The record shows a sender IP for each message only in threads with multiple IPs. For a thread with one IP or user agent, every agent message gets that value. Otherwise, the message's user agent is `null`. The record gives day and month only, so the year is 2026. The export checks that the thread headers, message tables and appendix totals agree. Its content is unredacted because it contains no credentials. The New York Times follow-up note is excluded from the record.

Reports are sorted by their earliest saved scan date, then report ID. Report IDs merge saved listings, full captures and derived inventories. `source_files` contains paths relative to the source directory. `raw_capture_available` distinguishes full captures from listing-only evidence.

A report qualifies when its saved report evidence, recorded destinations or recursively decoded carriers reference Amap or Gaode. Saved Amap API classifications also cover calls made through IP addresses. This includes proxies and redirect wrappers. `proxy_urls` and `has_proxy_evidence` identify proxy evidence inside qualifying reports; some reports may contain other traffic too. `match_basis` identifies the evidence used for selection.

`submitted_urls` and `final_urls` preserve observed variants. `evidence_urls` contains relevant Amap, carrier and proxy URLs. `requests` contains the recorded HTTP requests whose URLs reference Amap, Gaode, a proxy service, httpbin/httpbun or a base64 carrier when a full capture is available; `requests_total` counts every recorded request. `final_status`, `server_ip`, `server_asn`, `server_as`, `server_country`, `visibility`, `alert_count`, `user_agent`, `referer`, `exit_node`, `tags` and `requests_total` come from the report's fullest capture and are `null` for listing-only reports. `final_status` is the response to the last navigation to the final URL, or `null` when none was saved. `dates` preserves saved date representations as found. `scanned_at` is their earliest value as ISO 8601 UTC, treating values without an offset as UTC; minute-only listing dates count only when no finer time was saved, and it is `null` when no date was saved.

`decoded_payload_ids` joins to `payloads.jsonl`, which holds locally decoded UTF-8 payloads from httpbin-compatible `/base64/` endpoints, plus nested base64 and data-URI carriers. Decoding does not fetch or execute the content. Each payload has an ID calculated from its redacted content.

API keys, security codes, tokens, passwords and other named credentials are replaced with `[REDACTED]`. Original encoded carriers, long opaque strings and 32-character hexadecimal values are conservatively suppressed so they cannot bypass the plaintext redaction. Escaping and percent encoding are normalized during sanitization. These are evidence displays and may no longer be executable URLs or scripts.

Coverage includes saved structured JSON/JSONL, gzip JSON, CSV report inventories and report rows in saved HTML listings. The export does not claim to cover every report on URLQuery. See `summary.json` for decoding limits and any unreadable source files.

Rebuild from the project root:

```sh
python3 scripts/export_findings_amap.py
python3 scripts/export_findings_amap.py --refresh-provenance
python3 scripts/validate_findings_amap.py
python3 scripts/export_ntfy_amap.py
python3 scripts/export_webhooks_attachments.py
python3 scripts/validate_webhooks_attachments.py
python3 scripts/export_mailbox_conversations.py ~/Downloads/fleet-mailbox-conversations.docx
```
