# Rule authoring standard

Rules use a permanent `ASPL_` identifier; changing the semantic scope needs a
version change. Required metadata: author, source, license, description, category,
confidence, severity, rule_version, created, modified, status, scope, limitation,
minimum_yara. Confidence is confidence that the pattern is present; severity is
its security significance. Neither is a malware probability.

Use compound, format-aware conditions. For command rules, prefer bounded regex
windows over unrelated strings anywhere in a binary. Generic indicators do not
become independent evidence because several tools report them. Keep a filename
and reputation exception out of the rule conditions.

Write at least one positive and two distinct negative examples, UTF-8 and
UTF-16LE variants, and an exact quotation case. The quotation case is a disclosed
limitation, not a successful benign rejection. Full variable/data-flow or runtime
behavior cannot be established by these static textual rules.

All initial rules have `status = "experimental"` and `scope = "static-artifact"`.
Family attribution requires additional representative evidence and a separate
procedure. No family signature is fabricated to fill a category.
