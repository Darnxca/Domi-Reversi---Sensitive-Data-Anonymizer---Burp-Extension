# Extending Domi Reversi

Almost everything that decides *what is sensitive* lives in two JSON files, and every
behaviour is pinned by a JSON catalog of edge cases. You can extend both **without touching
Java** and, for your own installation, **without rebuilding the jar**.

| You want to… | Edit | Rebuild? |
|---|---|---|
| Hide a new kind of token / identifier | `patterns` | no (user file) |
| Hide the value of a new key (`"badge_id": …`) | `sensitive_json_keys` + `key_prefix_map` | no (user file) |
| Change how a header is treated | `sensitive_headers.json` → `strategies` / `keep` | no (user file) |
| Keep a public value readable (`127.0.0.1`) | `context.keep_values` | no (user file) |
| Teach it a new attack-payload syntax | `context.attack_markers` | no (user file) |
| Stop a word being taken for a client/user/name | `context.org_stop` / `not_usernames` / `not_names` | no (user file) |
| Hide the client name, a project code name | **Client / reserved terms** field in the UI | no |
| Pin a behaviour with a test | `src/test/resources/edgecases/*.json` | `./gradlew build` |

## User configuration (no rebuild)

Create `~/.domi-reversi/sensitive_patterns.json` and/or `~/.domi-reversi/sensitive_headers.json`
(or point `-Ddomireversi.config.dir=/path` at another folder). They use **the same format** as the
bundled files and are **added on top** of them: patterns, keys and list entries are appended,
header strategies and options replace the bundled ones. The extension only reads these files.
The status bar shows which user files were loaded.

```json
{
  "patterns": [
    {
      "name": "acme_badge",
      "prefix": "BADGE",
      "regex": "\\bACME-B\\d{6}\\b",
      "flags": ""
    }
  ],
  "sensitive_json_keys": { "exact": ["lat", "lng"], "contains": ["employeecode"] },
  "key_prefix_map": { "lat": "GEO", "lng": "GEO", "employeecode": "ID" },
  "context": {
    "keep_values": ["collaborator.internal-lab.example"],
    "attack_markers": ["\\bxp_cmdshell\\b"],
    "not_usernames": ["dashboard-v2"]
  }
}
```

## Detectors (`patterns`)

Applied in order, most specific first. Fields:

- `prefix`: placeholder type (`EMAIL` → `EMAIL_1`). Any `UPPER_CASE` word works.
- `flags`: `i` (ignore case), `m` (multi-line), `s` (dot matches newline).
- `keep_group`: number of a group at the **start** of the match that stays readable; only the
  rest is replaced. `/users/mario.rossi` with group 1 = `/users/` becomes `/users/USERNAME_1`.
- `validate`: extra check on the match — `card` (Luhn + card network), `iban` (mod 97), `phone`,
  `cf` (codice fiscale checksum, *omocodia* included), `piva` (VAT checksum), `plate`, `hex`, `b64`,
  `b64secret`; and, on the part
  after `keep_group`: `username`, `aduser`, `personname`, `hostname`, `pathtoken`.

Rules that keep Burp responsive: no unbounded repeated groups on arbitrary input (use `{0,200}`,
not `*`), and prefer a `keep_group` prefix to a variable-length look-behind.

## Context lists (`context`)

| List | Meaning |
|---|---|
| `org_stop` | Domain labels that are **not** the client (CDNs, SaaS, generic words) |
| `org_min_length` | A client name derived from a domain without `-` or digits needs this length |
| `two_level_suffixes` | Public suffixes like `co.uk`: the client name is the label before |
| `host_keys` | Keys whose value is a machine name (`db_host`, `upstream`) |
| `not_usernames` | Route segments after `/users/`, `C:\Users\` that are not people (`me`, `search`) |
| `not_names` | Words after a salutation that are not names ("Gentile *Cliente*") |
| `common_users` / `credential_hints` | When `user / value` in a comment is a credential |
| `keep_values` | Public, non-identifying values never replaced (loopback, cloud metadata) |
| `xmlrpc_credentials` | XML-RPC method (or prefix ending in `.`) → `[username position, password position]`, 1-based |
| `vcard_properties` | vCard / iCalendar property → placeholder type, hidden as a whole |
| `jwt_identity_claims` | JWT claims naming a person: if present, the claims are hidden too (the signature always is) |
| `attack_markers` | Regexes (case-insensitive) of attack syntax: such values are the tester's payloads and stay readable; e-mails, IPs and secrets inside them are still found |

## Edge-case catalog

`src/test/resources/edgecases/*.json` — one file per category, one entry per case. Every case
also checks that nothing throws and that request and response come back **byte for byte**.

```json
{
  "id": "org-in-path",
  "description": "Client name in a path segment",
  "severity": "critical",
  "request": "GET /acme-corp/reports HTTP/1.1\nHost: app.acme-corp.it\n\n",
  "response": "HTTP/1.1 200 OK\n\n...",
  "org_terms": ["Acme"],
  "level": "strict",
  "must_hide": ["acme-corp"],
  "must_keep": ["/reports"],
  "known_gap": "why this is not covered yet"
}
```

- `must_hide`: must not appear in the output (case-insensitive).
- `must_keep`: must appear unchanged — use it for false positives and attack payloads.
- `exact_roundtrip: false`: the response comes back as text, not bytes (e.g. gzip bodies).
- A `response` starting with `### Domi Reversi` is a transcript (WebSocket, Scanner issue): blocks
  separated by `### ...` lines, each anonymized by content.
- `known_gap`: documented limitation. It does not fail the build while it fails, and **fails the
  build as soon as it passes**, so the catalog never lies.
- De-anonymization cases use `map`, `llm_text`, `expect`, `expect_unknown`, `expect_altered`.

`./gradlew build` writes `build/reports/edgecases/report.md` (summary per category, every case).
