# Validation and limits

`scripts/library.py test` compiles the entire library using both engines. Each
rule has UTF-8/UTF-16 positive, negative, and exact-documentation-quote cases.
The intended rule's presence or absence is asserted, and complete engine match
lists must agree. Every negative fixture must return no rules across the full
library. Positive examples may match another related rule; all overlap
is recorded rather than hidden. A shared benign text corpus is scanned against
every rule and must return no matches.

Tests also include a one-MiB repeated-anchor scan, require unique identifiers and metadata, record input/bundle SHA-256,
engine versions, scan timings and compiler warnings. Timeout is ten seconds per
scan. Results are generated into `outputs/validation.json` and uploaded by CI.

This synthetic corpus establishes tested artifact behavior, not real-world
precision, recall, safety or production readiness. Legitimate administration,
credential export, and quoted scripts can satisfy these conditions. The library
cannot prove execution, variable relationships, intent or campaign attribution.
No live malware is stored or executed. Real benign corpus validation and broader
suspicious sample review remain acceptance work before stable integration.

## Initial local evidence

On Windows with Python 3.12, yara-python 4.5.4 and yara-x 1.21.0, the initial
60 rules passed 525 checks with zero compiler warnings: 120 positive variants,
280 negative variants, 120 quoted-documentation variants, four shared benign
text files, and one repeated-anchor cost probe. Quotation matches are explicitly
expected limitations and are not counted as successful benign rejection.
Remote Windows/Ubuntu CI provides a separate signal for each published commit.
