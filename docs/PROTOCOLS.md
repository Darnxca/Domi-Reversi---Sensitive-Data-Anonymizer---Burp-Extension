# What goes through Burp, and how Domi Reversi handles it

Every row is pinned by cases in `src/test/resources/edgecases/` (category in brackets), so this
table cannot silently drift from the code. "Exact" means de-anonymization returns the original
bytes; "text" means it returns a readable decoded form (binary formats, compressed bodies).

## Transport and framing

| Traffic | Handling | Round trip |
|---|---|---|
| HTTP/1.x request/response | headers by strategy, body by content type | exact |
| HTTP/2 (as shown by Burp, pseudo-headers `:authority`, `:path`) | `:authority` treated as Host | exact |
| `Transfer-Encoding: chunked` | original chunk framing kept; data after the last chunk (smuggling) preserved | exact |
| Header continuation lines (obs-fold) | same strategy as their header | exact |
| `Content-Encoding: gzip`, `deflate` | decompressed, then anonymized | text |
| `Content-Encoding: br`, `zstd` | not in the JDK: body left as is (Burp usually shows it decompressed) | exact |
| UTF-16 bodies (with or without BOM) | decoded, anonymized, re-encoded | exact |
| WebSocket (handshake + messages) | right-click in WebSocket history: transcript with direction | exact |

## API styles [Protocolli e formati, Attacchi web]

| Traffic | Handling |
|---|---|
| REST / JSON, JSON:API, HAL, NDJSON, JSON in strings, truncated JSON | structure-preserving rewrite, keys decide |
| GraphQL: POST JSON, `application/graphql`, GET `?query=`, batches, Apollo persisted queries, multipart upload, `errors` | query kept readable, inline arguments and variables anonymized |
| GraphQL introspection (`__schema`, `__type`) | type and field names stay readable |
| GraphQL over WebSocket (graphql-ws), subscriptions | as WebSocket JSON frames |
| JSON-RPC 2.0 | JSON rules (`params` by key) |
| XML-RPC (WordPress `xmlrpc.php`, `system.multicall`) | positional credentials per method (`context.xmlrpc_credentials`), struct members by name |
| SOAP 1.1/1.2, WS-Security, SAML | XML rules, base64 SAML decoded |
| OData (`$filter`, `$select`) | URL-decoded query values scanned |
| Server-Sent Events (`text/event-stream`) | `data:` lines scanned, JSON by key |
| JSONP, inline JS state (`window.__INITIAL_STATE__`), JS objects | key/value rules on JS syntax |
| Forms: urlencoded, multipart (file names too) | by field name |
| Socket.IO, STOMP, SignalR (JSON), graphql-ws | WebSocket transcript, per-frame type detection |

## Binary formats

| Traffic | Handling | Round trip |
|---|---|---|
| gRPC (`application/grpc`), gRPC-web, gRPC-web-text | frames decoded, protobuf rendered like `protoc --decode_raw`; trailers scanned | text |
| Protobuf (`application/x-protobuf`) | schema-less decoding; `map<string,string>`/`Struct` keys guide the values | text |
| MessagePack | decoded to JSON, key rules apply | text |
| BSON, AMF (Flex/BlazeDS), Hessian, WCF binary XML (msbin1), CBOR, Thrift | printable runs in place: a run after a sensitive field name is its value; password-shaped runs hidden | exact |
| Java / .NET / pickle / Ruby / PHP serialized objects | readable when the strings inside hold nothing sensitive; hidden in cookies | exact |
| Other binaries (`application/octet-stream`, dumps) | same printable-run scan plus all detectors | exact |

## Content that is often personal data

| Traffic | Handling |
|---|---|
| CSV / TSV exports | column header decides the column |
| vCard (CardDAV), iCalendar (CalDAV) | properties by name (`context.vcard_properties`), `CN=` parameters |
| WebDAV (Nextcloud, ownCloud, SOGo) | user names in `/remote.php/dav/files/<user>/` |
| LDIF / LDAP results | DNs, `{SSHA}` and other password hashes |
| Prometheus `/metrics`, logs, stack traces | IPs, hosts, paths, user directories |
| Scanner issues | right-click: detail, background, remediation, request |

## Known limits

- **Compressed archives and documents** (ZIP, Office, PDF uploads) and **image metadata** (EXIF)
  are not opened: only their visible strings are scanned.
- **Avro** and **Thrift** carry no field names: only values with a recognizable shape (e-mail,
  token, password-like) are found.
- **Brotli / zstd** bodies: not decompressed (no dependency added); Burp normally decompresses them.
- **Free-text names without context** ("assigned to Luca Verdi"): add them with the
  *Client / reserved terms* field or select and press Ctrl+Shift+A.
