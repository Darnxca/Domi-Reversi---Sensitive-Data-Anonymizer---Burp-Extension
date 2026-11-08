# Contributing

Thanks for helping make Domi Reversi better.

## Requirements

- JDK 17 or newer (CI runs on 17 and 21, Linux and Windows)
- No other installs: the Gradle wrapper downloads everything it needs

## Build and test

```bash
./gradlew build                 # compile, unit tests, adversarial round-trip, GraphQL, jar
./gradlew audit -PstrictAudit   # extended audit (~2400 generated cases), fails on any error
```

The extension jar is written to `build/libs/`. Reports:

| Report | Path |
|---|---|
| Unit tests | `build/reports/tests/test/index.html` |
| Audit | `build/reports/audit/index.html` |
| Adversarial round-trip | `build/reports/adversarial/report.md` |
| Edge-case catalog | `build/reports/edgecases/report.md` |

## Project layout

```
src/main/java/com/domireversi/
  DomiReversiExtension.java   Burp entry point (Montoya API)
  DomiReversiMenu.java        right-click menu
  core/                       anonymization engine (no Burp dependency)
    Anonymizer.java           pipeline: headers, bodies, patterns, reversibility
    SubstitutionMap.java      consistent, reversible placeholders
    HttpMessage.java          byte-preserving HTTP parser
    Config.java               loads the JSON rules below (+ user files in ~/.domi-reversi)
    MapFile.java              map export / import
  ui/DomiReversiTab.java      Swing user interface
src/main/resources/
  sensitive_headers.json      header strategies
  sensitive_patterns.json     detectors, sensitive keys, levels
src/test/                     unit, audit, adversarial and GraphQL tests
src/test/resources/edgecases/ data-driven edge-case catalog (one JSON entry per case)
docs/EXTENDING.md             how to add detectors, keys, context lists and cases
```

## Rules for changes

- **Every fix or new detector needs a regression test.** The quickest way is an entry in
  `src/test/resources/edgecases/*.json` (`must_hide`, `must_keep`; round trip is checked
  automatically). Generated leak tests go in `AnonymizationAuditTest`, exact-reversibility cases
  in `AdversarialRoundTripTest`.
- **Pentest-aware:** a payload the tester wrote must stay readable (add a `must_keep`), the data
  it exfiltrates must disappear (add a `must_hide`).
- **Exact reversibility:** `deanonymize(anonymize(message)) == message` byte for byte.
  Never "normalize" input (whitespace, encodings, line endings).
- **No unbounded repeated groups in regexes** applied to arbitrary input: they can
  freeze Burp or overflow the stack. Prefer linear scanners.
- **Never commit real client data**, not even in tests or screenshots.
- Keep the engine (`core/`) free of Burp/Swing dependencies so it stays testable.

## Releasing

1. Update `CHANGELOG.md` and the version in `build.gradle`.
2. Run `./gradlew build audit -PstrictAudit` and check everything is green.
3. Tag and push: `git tag v1.2.0 && git push origin v1.2.0`.
4. Publish the release: either run the *Release* workflow manually from the Actions tab,
   or create the release on GitHub and attach `build/libs/domi-reversi-burp-<version>.jar`
   with its SHA-256 checksum.
