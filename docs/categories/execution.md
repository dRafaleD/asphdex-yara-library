# Execution, web shell, and exploit action artifacts

These 20 original rules flag narrow textual combinations for analyst review. They cover script and proxy execution artifacts (10), request-to-command web shell source patterns (6), and build/document action artifacts (4). Names describe observed syntax and never assert a malware family. The exploit-artifacts folder contains potential action surfaces, not CVE signatures or evidence that exploitation succeeded.

## Review procedure

Scan extracted source or visible text without running it. Review the exact matched bytes, offsets, surrounding syntax, and origin. For extracted Office XML or decoded documents, record the extraction method and distinguish extracted-text offsets from original-file offsets. Determine whether matches occur in comments, a quoted example, a test fixture, or active source. Authorized administration, template systems, and inline MSBuild tasks can contain similar constructs.

Each rule links to an official MITRE ATT&CK technique for context. The source is not a validation of the original signature. Relevant primary context includes [PowerShell](https://attack.mitre.org/techniques/T1059/001/), [Web Shell](https://attack.mitre.org/techniques/T1505/003/), and [Regsvr32](https://attack.mitre.org/techniques/T1218/010/).

Every rule requires all of its strings, with every companion string located after a matching anchor within 4096 bytes. ASCII and UTF-16LE text are accepted case-insensitively. Files larger than 4 MiB fall outside the rule scope. The order and byte window constrain matches but do not establish data flow. Absence of a match is not a clean verdict. Token spacing, aliases, intervening comments, compression, encryption, encoded bodies, and reordering can evade these narrow patterns.

## Fixture safety and validation limits

The specifications in tests/specs/execution.json are synthetic INERT text with incomplete literal markers separated by inert labels. They are test data, never executable samples. Each rule has a positive case, a near miss missing its last required marker, and a relevant benign-context case, tested in UTF-8 and UTF-16LE. Tests measure literal matching and targeted rejection, not real-world accuracy. Full matching examples copied into educational documents may match and require contextual review. All rules are experimental, with confidence at most medium.

Execution rules identify launcher, reflection, deserialization, interpreter, or script-host markers. Web shell rules focus on request syntax next to command/evaluation syntax. Build/document rules flag inline task, XSL scripting, DDE, or PDF automatic-script markers. None reconstructs a full execution chain or resolves variable assignment or control flow.
