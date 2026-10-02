# AsphDex YARA Library

An independent, versioned library of original YARA rules for defensive static
file review. Rules are grouped by technique, ship with inert text fixtures, and
are checked with both YARA and YARA-X. This repository is separate from the
[AsphDex desktop application](https://github.com/dRafaleD/Malware-analysis-AsphDex).

## Status

**Experimental v0.1.0.** The initial collection contains 60 static artifact rules
across execution, webshells, exploit artifacts, credential access, collection,
remote access, persistence, defense evasion, impact, and script obfuscation.
These are behavior artifacts, not verified malware-family signatures. A match
does not prove execution, malicious intent, or independent confirmation.

Every rule has a procedure, attribution, license, severity/confidence metadata,
positive and negative fixtures, and a documented limitation. Full command quotes
in documentation can match; legitimate administrative/export tools may match.
Synthetic fixtures do not establish real-world accuracy.

## Layout

| Path | Purpose |
| --- | --- |
| `rules/behavior/` | Technique and command/content artifacts |
| `rules/packers/` | Script obfuscation artifacts; not malware verdicts |
| `rules/families/` | Reserved for independently supported family signatures |
| `main.yar` | Generated source entry point |
| `catalog.json` | Rule identifiers, categories and metadata |
| `tests/specs/` | Reviewed inert fixture definitions |
| `tests/fixtures/` | Generated ASCII/UTF-16 `.txt` fixtures |
| `tests/benign/` | Shared small synthetic benign corpus |
| `docs/categories/` | Category-specific rule procedures |
| `scripts/library.py` | Build category bundles, validate and record results |

## Test and build

Use Python 3.12 and the pinned test dependencies:

```bash
python -m venv .venv
# Linux: .venv/bin/python; Windows: .venv/Scripts/python.exe
.venv/bin/python -m pip install -r requirements-test.txt
.venv/bin/python scripts/library.py test
```

On Windows PowerShell, replace `.venv/bin/python` with `.\.venv\Scripts\python.exe`.
Fixture content is only encoded and scanned as bytes. No sample is executed and
no live malware is downloaded. Results appear in `outputs/validation.json`.

`python scripts/library.py build` creates a combined `.yar`, category `.yar`
bundles, a checksum manifest and an experimental ZIP under `dist/`. For native
YARA, scan with `yara main.yar file-to-inspect` from the repository root, or use
the standalone combined bundle. Rule regexes exceed the browser JS fallback's
capabilities; AsphDex must report unsupported rules as limited coverage.

## Procedures and contribution

Start with [category policy](docs/categories.md), [rule authoring](docs/rule-authoring.md),
[compatibility](docs/compatibility.md), and [validation](docs/validation.md).
See [CONTRIBUTING.md](CONTRIBUTING.md) for fixture and review requirements.
Do not submit live samples, secrets, or third-party rules without a compatible
license. Original rules use the [ISC license](LICENSE).

Publishing this library does not enable it in AsphDex or change desktop scores.
Application integration must pin a reviewed release and retain the metadata,
coverage limitations and evidence deduplication.
