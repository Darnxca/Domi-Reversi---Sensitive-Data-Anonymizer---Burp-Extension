# Domi Reversi — Sensitive Data Anonymizer

A Burp Suite extension that anonymizes HTTP requests and responses so you can share
them with an external LLM (for pentest advice, debugging, or write-ups) **without
leaking your client's sensitive data**.

It replaces hosts, credentials, tokens, cookies, IP addresses and PII with
consistent, reversible placeholders (`HOST_1`, `IP_1`, `EMAIL_1`,
`AUTH_TOKEN_1`, …) while keeping the original structure intact — so what you paste
into the model still looks like a real message and the advice stays relevant. A
substitution map lets you reverse the placeholders, and a **De-anonymize** tab
turns the model's reply back into the real values.

Everything runs locally inside Burp. The extension does **not** integrate with or
call any AI service and makes no outbound connections of its own — it only produces
the redacted text; where you paste it afterwards is entirely your choice.

## Features

- Anonymize straight from the **context menu** (Proxy history, Repeater, …) or by
  pasting raw HTTP into the dedicated tab. Choose **request + response**, **request
  only**, or **response only**.
- **Selective header redaction** — the header name stays visible, only the value is
  masked: `Host`, `Authorization`, `Cookie`/`Set-Cookie` (per-cookie, names kept),
  the forwarding family (`X-Forwarded-For`/`-Host`, `Forwarded` — both IPs and
  internal hostnames), API-key and CSRF/auth-token headers,
  `WWW-Authenticate`/`Proxy-Authenticate`, and stack-disclosing banners (`Server`,
  `X-Powered-By`, version headers). Harmless headers are left untouched so the
  message stays readable.
- **Body redaction by format**: JSON (sensitive keys at any depth), form-urlencoded
  (percent-decoded first), multipart/form-data (nested, filenames,
  base64/quoted-printable parts), HTML/XML, GraphQL (inline literals and variables),
  and `Transfer-Encoding: chunked` (correctly reassembled, multibyte-safe).
- **Pattern detection** anywhere in the message: emails, IPv4/IPv6, credit-card
  numbers (Luhn-validated), IBAN, JWTs, PEM private keys, provider API keys (AWS,
  Google, Stripe, GitHub, Slack, Twilio, …), Italian Codice Fiscale / P.IVA, and
  phone numbers.
- **Consistent, reversible placeholders**: the same value always maps to the same
  placeholder across headers and body, request and response.
- **De-anonymize** tab: paste the model's reply and recover the real values from the
  last substitution map.
- **Full user control**:
  - the substitution map is a table with a checkbox on every row — untick any value
    you'd rather keep in clear (an open-source server banner, a chatbot name) and it
    re-runs instantly;
  - for anything the rules missed, select the text and press **Ctrl+Shift+A**
    (or right-click → *Anonymize selection*) — every occurrence becomes `CUSTOM_1`,
    `CUSTOM_2`, …
- **English / Italian** user interface.
- Fully offline and self-contained — a single jar with everything bundled, no
  configuration and no network calls.

## Requirements

- Burp Suite (Community or Professional) with a recent JRE.
- To build from source: a JDK 17 or newer.

## Building

The project uses Gradle. From the repository root:

```bash
./gradlew shadowJar
```

This produces a self-contained jar at:

```
build/libs/domi-reversi-burp-1.0.0.jar
```

The [Montoya API](https://portswigger.github.io/burp-extensions-montoya-api/) is
`compileOnly` (Burp provides it at runtime); Gson is bundled and relocated to avoid
conflicts with Burp or other extensions.

## Installing

In Burp: **Extensions → Installed → Add** → *Extension type:* **Java** → select the
jar. A **Domi Reversi** tab appears and a new right-click menu entry is added.

## Usage

1. In Proxy history / Repeater, **right-click** a request/response and choose
   *Anonymize (request + response)* — or *request only* / *response only*. It opens
   in the tab, already anonymized. You can also paste raw HTTP into the tab and press
   **Anonymize**.
2. Review the output, then open the **Substitution map** tab to see each
   `original → placeholder`. Untick any value you want to keep in clear — the output
   updates immediately.
3. Missed something? Select it in the input and press **Ctrl+Shift+A** (or
   right-click → *Anonymize selection*). Every occurrence is replaced with a
   `CUSTOM_n` placeholder.
4. Copy the anonymized request/response and paste it into your LLM of choice.
5. When the model replies referring to placeholders (`HOST_1`, `IP_2`, …), paste its
   answer into the **De-anonymize** tab to restore the real values.

## How it works

The same original value always receives the same placeholder — in the Host header,
in a `Referer`, in a `Set-Cookie` domain, and in URLs inside the body. Because the
mapping is kept, it is reversible: the substitution map (and the De-anonymize tab)
turn placeholders back into the original values. Non-numbered redactions used for
information disclosure (e.g. `Server` banners shown as `REDACTED`) are intentionally
not reversible.

No automated redactor is perfect: always review the output before sharing it, and
use the map checkboxes or manual selection to correct anything.

## License

Released under the [MIT License](LICENSE).