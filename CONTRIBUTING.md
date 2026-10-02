# Contributing

Submit a small, reviewable group of original rules with an authoritative source
and the category procedure. Include two encoding variants, at least two negative
examples, and a documented quotation limitation in `tests/specs/`. Run
`python scripts/library.py test`; both engine outputs must agree.

Use `ASPL_` identifiers and complete metadata. Add no wildcard-only signature,
single generic API detection, artificial family attribution, filename/publisher
allowlist, or unbounded regex. Sources identify the technique, not a copied
signature. Preserve licensing and attribution when proposing third-party code.

Keep tests inert: text only, `.invalid` destinations, no executable samples or
network connections. Full-text command quotes may match and must be disclosed.
Case-level false positives are an issue to investigate, not a reason to relabel
the sample or loosen acceptance thresholds.

The initial rules remain experimental until a broader lawful benign corpus and
representative suspicious corpus have been independently reviewed. A PR must
explain detection scope, known near misses, overlap, and measured scan costs.
