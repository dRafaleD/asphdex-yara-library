# Persistence, defense evasion, recovery impact, and script obfuscation

This group contains 20 original experimental rules: five persistence artifacts,
six defense-evasion artifacts, five recovery-impact artifacts, and four script
obfuscation artifacts. Every rule uses a literal anchor and a bounded same-line
command pattern, supports ASCII and UTF-16LE, and rejects files of 20 MiB or more.
The size limit is a scope limit, not evidence that larger files are safe.

## What the rules cover

| Group | Static patterns |
| --- | --- |
| Persistence | Registry Run interpreter assignment; Winlogon Shell assignment; remote UNC service executable; task interpreter action plus trigger; executable copied into Startup |
| Defense evasion | Defender realtime monitoring disabled; temporary-directory exclusion; Security/System log clearing; success and failure auditing disabled; firewall profiles disabled; AMSI initialization flag reflection assignment |
| Recovery impact | All shadow copies deleted by vssadmin; WMIC shadowcopy deletion; boot recovery disabled with failure-ignore policy; zero retained backup versions; backup catalog deletion |
| Script obfuscation | PowerShell base64 expression evaluation; numeric character-array expression evaluation; JavaScript base64 eval; gzip stream decompression followed by reflection loading |

The four files under `rules/packers/` intentionally describe **obfuscation
artifacts**. They do not identify a named packer, validate a packed binary, or
establish maliciousness. Their metadata category is `obfuscation`, and severity
and confidence are low. A base64 string or a compression API alone is insufficient.

## Reviewing a match

1. Inspect the exact matched bytes, offsets and original file type. Confirm that
   the artifact is present in the file actually under review.
2. Check whether the bytes are a command, a quoted example, a comment, generated
   resource text, or an administrative procedure. Static byte matching does not
   make this distinction automatically.
3. Confirm the operational context separately: actual registry/task/service state,
   authorized maintenance, enabled audit policy, backup inventory or a documented
   change. Never infer that a destructive command ran from a YARA match alone.
4. For obfuscation matches, inspect decoded content only with safe byte-oriented
   tooling. Do not evaluate expressions or load assemblies to validate a match.
5. Record both supporting evidence and a plausible benign explanation. Several
   rules may describe a single command chain; they are not independent evidence
   and should not be added repeatedly to a risk score.

## Known limits

- These are narrow command forms. Different switch order, aliases, line breaks,
  encodings, environment expansion, escaped identifiers or runtime construction
  can evade them. A non-match is not proof of safety or a completed behavior check.
- Bounded co-location does not establish variable identity or data flow. For
  example, the gzip output variable is not tied semantically to the reflection
  input, and a reflection field assignment is not proven to have executed.
- Approved kiosk changes, scheduled maintenance, firewall testing, recovery
  repair, backup rotation, temporary-directory exclusions and code generators
  can match. Even potentially damaging command forms have legitimate uses.
- Exact command chains inside documentation or comments can match. Such examples
  must be kept as documented limitations rather than counted as false-negative
  or true-malware claims.
- The regex syntax is intended for native YARA 4.5+ and YARA-X. A partial browser
  engine that does not implement regex must mark these rules unsupported and
  coverage limited; zero matches must not imply a complete scan.
- `confidence` concerns the presence of the specified pattern, not the likelihood
  of malware. `severity` concerns the operation's significance, not a verdict.

## Test specifications

`tests/specs/persistence-impact.json` defines one inert positive and two negative
near-miss/benign snippets per rule, in UTF-8 and UTF-16LE. The library runner
materializes `.txt` fixtures and scans bytes only. Negative examples include
query operations, enabled settings, ordinary backup paths and decoded-text display
without execution. Sample content must never be invoked as a program or shell.

This synthetic set checks rule mechanics; it does not measure real-world detection
rates, false-positive prevalence, or compatibility with every legitimate tool.
Validate native YARA and YARA-X results, metadata, benign references and licensing
before changing experimental status or integrating these rules with a product.

All rules are original ISC-licensed work. Their `source` fields link directly to
the relevant MITRE ATT&CK technique pages: persistence mechanisms, impairment of
defenses, Windows event-log clearing, recovery inhibition and obfuscation.
