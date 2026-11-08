# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Client identity.** The base name of the target domain (`acme-corp` from `app.acme-corp.it`)
  becomes `ORG_n` everywhere it appears, in any spelling (`Acme Corp`, `acmecorp`, `ACME-CORP`):
  paths, custom headers (`X-Tenant`), Java packages, free text. A new **Client / reserved terms**
  field adds names that cannot be derived from a domain (short brand names, project code names).
- **Internal infrastructure.** Host names without a TLD under host-like keys (`db_host`, `server`,
  `upstream`…), UNC paths (`\\fs01\share`), Windows domain users (`ACME\m.rossi`), user profile and
  home directories (`C:\Users\…`, `/home/…`), connection-string servers, LDAP DNs.
- **Web attacks.** Attack payloads (SSTI, SQLi, NoSQLi, XSS, CRLF, traversal, XXE, JNDI, command
  injection…) are recognized by configurable `attack_markers` and stay readable even under a
  sensitive key, while data exfiltrated in the response is hidden: `/etc/passwd` users and GECOS
  names, `/etc/shadow` and other crypt hashes, `id` output, Spring Actuator `name`/`value` pairs,
  cloud-metadata credentials. Well-known non-identifying addresses (`127.0.0.1`,
  `169.254.169.254`, `metadata.google.internal`, public cloud suffixes) stay readable (`keep_values`).
- **More secrets and PII:** Azure AD client secrets, Vault, Doppler, PyPI, Docker Hub, Postman,
  Grafana, New Relic, DigitalOcean, Databricks, Atlassian, Square, Facebook, Twitter/X, HubSpot,
  Dropbox, Notion, Figma, Linear, Supabase, Sentry DSN keys; Bitcoin/Ethereum wallets; passport,
  ID card, driving licence and NHS numbers, health data by key; usernames in URL paths, tokens in
  sensitive paths (`/reset-password/<token>`, `/session/<uuid>`), names after a salutation,
  passwords left in HTML/JS comments, plates by key. Codice fiscale with *omocodia* and checksum.
- **Pentest-readable JWTs.** The signature is always replaced (the token can no longer be
  replayed); header and claims stay readable when, decoded, they hold nothing sensitive and no
  identity claim (`sub`, `upn`, `preferred_username`… in `jwt_identity_claims`) names a person.
  `alg:none`, `kid`, roles and expiry are visible to the LLM.
- **Serialized objects** (Java, .NET BinaryFormatter, pickle, Ruby Marshal, PHP) stay readable when
  the strings inside them hold no sensitive data; in cookies they stay hidden (they are credentials).
- **Version banners are readable** (`Server`, `X-Powered-By`, `X-AspNet-Version`…): the version is
  what the LLM needs to look up CVEs. Hosts and IPs inside banners and in `Via` /
  `X-Backend-Server` are still replaced.
- **Client name glued by underscores** (`acmecorp_sid`, `acme_corp_exports`): the whole word becomes
  `ORG_n_W`, same root, still exactly reversible.
- **From [rizzo-pii](https://github.com/Rizzo-AI-Academy/rizzo-pii)** (rules and tests adapted to
  HTTP): bodies in **UTF-16** (readable on screen, invisible to the detectors) are decoded,
  anonymized and re-encoded; **CSV/TSV exports** are anonymized by column header; IBANs printed in
  groups use the per-country length (ISO 13616) and may wrap once; cards with dots or with the
  expiry date attached; Italian plates in text; protocol / R.G. numbers; date of birth in text;
  VAT number (P.IVA) with checksum; the same name written with different case or spacing gets
  one placeholder.
- **Beyond HTTP pairs.** Right-click **WebSocket messages** (handshake + transcript with direction;
  JSON, Socket.IO, STOMP, graphql-ws, SignalR frames), **Scanner issues** (detail, background,
  remediation and the request) or **several HTTP messages at once** (same session, **Copy session**
  copies them all).
- **gzip / deflate bodies** are decompressed and anonymized (the round trip returns the text).
- **Protocols and formats** (inventory in `docs/PROTOCOLS.md`): gRPC, gRPC-web, gRPC-web-text and
  protobuf decoded schema-less like `protoc --decode_raw`; MessagePack decoded to JSON; BSON, AMF,
  Hessian, WCF msbin1, CBOR, Thrift and other binaries scanned in place (a value after a sensitive
  field name is hidden, password-shaped strings too); XML-RPC positional credentials per method
  (`context.xmlrpc_credentials`, WordPress and `system.multicall` included) and struct members;
  vCard / iCalendar properties and `CN=` parameters (`context.vcard_properties`); WebDAV / Nextcloud
  user paths; LDAP password hashes; GraphQL introspection keeps type and field names readable.
- **Saved in the Burp project**: client field, session and map survive a restart; the session
  resumes with the same placeholders, so older LLM replies never restore to another session's values.
- **Continuous session.** Consecutive messages share one map, so `HOST_1` is the same host for the
  whole chat with the LLM and every earlier reply can still be de-anonymized. **New session**
  starts over.
- **De-anonymization diagnostics.** Markdown-escaped placeholders (`HOST\_1`) are restored;
  placeholders altered (`host_1`, `HOST_1s`) or invented (`HOST_9`) by the LLM are reported and
  never guessed.
- **Map export / import** (JSON, only when the user asks) to de-anonymize replies days later;
  malformed maps are rejected as a whole. Idea taken from
  [rizzo-pii](https://github.com/Rizzo-AI-Academy/rizzo-pii), like the codice fiscale checksum.
- **User configuration** in `~/.domi-reversi/` (or `-Ddomireversi.config.dir`), added on top of the
  bundled rules: new detectors, keys and context lists without rebuilding the jar. All context lists
  (`org_stop`, `host_keys`, `not_usernames`, `keep_values`, `attack_markers`…) moved to JSON.
- **Data-driven edge-case catalog** (`src/test/resources/edgecases/*.json`, 312 cases in 14
  categories, including one per web-attack class) with a Markdown report; a case is one JSON entry.

### Changed
- `REDACTED`-strategy headers default to an empty list (see above); put headers back in
  `strategies.redact` to hide them again.

### Fixed
- `Transfer-Encoding: chunked`: the anonymized body keeps the original chunk framing, so
  de-anonymization is byte-exact again; data after the last chunk (request smuggling) is no longer
  dropped.
- Header continuation lines (obs-fold) are anonymized with the strategy of their header.
- Numbers under sensitive JSON keys are no longer turned into quoted strings (exact round trip).
- `REDACTED` values (server banners, `WWW-Authenticate` realms) are numbered and reversible.
- IPv6 detector no longer matches runs of `:` in colon-separated records.
- A value can no longer swallow a placeholder emitted earlier (`CN=Mario Rossi:mailto:EMAIL_1`):
  nested placeholders could not be restored exactly.
- A JSON `"name"` holding a property name (`spring.datasource.password`) is not a person's name.

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
