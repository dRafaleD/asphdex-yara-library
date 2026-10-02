# Engine compatibility

The test dependencies pin yara-python 4.5.4 and yara-x 1.21.0. CI checks Windows
and Ubuntu with Python 3.12; the initial minimum rule syntax target is YARA 4.5.
Passing on tested versions does not prove every older version is compatible.

The library uses classic YARA-compatible syntax and tests the same bytes on both
engines. See the upstream [YARA-X language documentation](https://virustotal.github.io/yara-x/docs/writing_rules/)
and [Python API](https://virustotal.github.io/yara-x/docs/api/python/).

AsphDex's browser fallback supports only a subset. These regex rules require a
native engine. Unsupported rules must be reported as skipped/limited; absence
of a fallback match is not a completed native scan.

Bundles preserve metadata; integration should pin a tagged release and validate
the SHA-256 manifest. This repo does not change AsphDex's signed-update trust
keys or enable an automatic update feed.
