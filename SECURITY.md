# Security policy

Domi Reversi exists to keep client data out of third-party tools, so a value that
slips through anonymization is treated as a security issue.

## Reporting

Please report privately through
[GitHub security advisories](https://github.com/Darnxca/Domi-Reversi---Sensitive-Data-Anonymizer---Burp-Extension/security/advisories/new)
rather than opening a public issue.

Include a **synthetic** reproduction: replace every real value with a fake one of
the same shape. Never send real client traffic.

Useful details:

- extension version and Burp Suite version;
- the smallest HTTP request/response that reproduces the problem;
- what leaked (or what was altered) and where.

## Scope

In scope: sensitive values left in clear, non-reversible or corrupted output,
crashes or freezes triggered by crafted traffic.

Out of scope: data the user deliberately kept in clear (unchecked in the
substitution map) and values the user chose to share.

## Design notes

- The extension makes no network connections and stores nothing on disk.
- The substitution map lives in memory for the current session only.
- No automated redactor is perfect: always review the output before sharing it.
