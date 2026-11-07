# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-11-07

### Added
- Exact reversibility: `deanonymize(anonymize(message))` rebuilds the original byte for byte,
  including header whitespace, JSON escapes and percent/HTML-encoded values
  (encoded forms get variants such as `EMAIL_1_URL` that share the same root).
- Literal placeholder-like text already present in traffic (e.g. `EMAIL_1`) is never confused
  with generated placeholders.
- Anonymization levels: *Standard* keeps identifiers (`id`, `*_id`, `*Id`, `*_ref`, hashes,
  tracing headers) readable for debugging; *Strict* replaces them with `ID_n`.
  `preserve_keys` lists fields that are never touched.
- GraphQL lexer: keywords, operation names, variables, types, fields, arguments, aliases,
  directives and fragments are preserved; only literal values are anonymized.
- Key/value detection in any format: HTML/XML attributes, hidden inputs, meta tags,
  JavaScript, YAML, NDJSON, `key=value` text, connection strings.
- New detectors: AWS secret keys, GitLab, SendGrid, npm, Telegram, Slack/Discord webhooks,
  MAC addresses, spaced IBANs, contextual VAT numbers, SSN, base64-encoded personal data.
- Known values found in structured fields (e.g. a name) are also replaced in free text.
- UI: highlighted replacements, placeholder tooltips, per-pane copy buttons and counters,
  map search, level selector, Burp editor font, background processing.
- Extended audit suite (~2400 generated cases), adversarial round-trip test,
  GraphQL preservation tests, GitHub Actions CI, release and CodeQL workflows.

### Changed
- Tolerant JSON rewriter that preserves the original formatting and `null` fields.
- Linear host/domain scanner (no more freezes with thousands of hosts).
- `Content-Length` is no longer rewritten, so output stays exactly reversible.

### Fixed
- Crash on long dotted strings and freezes on large responses.
- Placeholders anonymized twice in HTML URLs.
- Credit-card regex swallowing the following space; phone false positives on dates,
  versions and User-Agent strings.
- HTML labels shown as raw markup inside Burp.

## [1.0.0]

- First release.
