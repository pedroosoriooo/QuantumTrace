# QuantumTrace 0.3 — validation record

Dataset: [JunctionX-QuantumTrace](https://github.com/joaoalves3901/JunctionX-QuantumTrace),
snapshot `39e8f18dcfb5edc66eda0f47bb44884aa7db5c9c`, checked on 2026-10-10.
All 35 bundled files are unchanged from the supplied repository snapshot.
The dataset is synthetic; input source files were not executed.

## Verified behavior

86 automated tests passed with Python 3.12.14 and TShark 4.2.2. The checks
include manually defined expectations for the supplied examples; there are no
official ground-truth labels or competition accuracy measurements.

| Check | Result |
|---|---|
| Known primitive families in 24 Python/Java/Go source files | 24/24 match manual expected sets |
| Six AES source examples | Inferred 128/256-bit sizes match the specific literals, generators and observed calls |
| KMS inventory | All 10 KeySpec entries identified; four declared symmetric AES-256 keys |
| ELB TLS policies | Five named policies mapped to configured capabilities |
| Synthetic PCAP | 97 ClientHello/ServerHello pairs; offers and selections kept separate |
| Hybrid selected groups | Seven X25519MLKEM768 sessions; both components recorded |
| Provenance | Source lines, JSON pointers, file hashes, frames, streams and endpoints |
| Input processing | 28 analysed, zero errors, zero partial files; seven metadata files unsupported |
| Context-aware policy | Collision/preimage distinction; known ChaCha20 key size; PBKDF2 output length distinct from entropy |
| HTTP upload and scanning | Real server accepts files, scans passively and returns reports; source not executed |
| Input/session handling | Foreign origins, missing token, traversal and malformed base64 rejected |
| Persistence/comparison | Reports restored from SQLite; identical runs have zero changes; changed inputs and policies distinguished |
| Configured-suite comparison | Different suites at the same policy locator retain separate observation identities |
| History deletion | One/all reports removed persistently; other reports and original files preserved; clearing covers entries beyond the display limit |
| Deletion/session handling | Missing token, foreign origin and invalid DELETE routes rejected; deletion blocked while a scan runs |

## Results and policy change

**1574 observations = 619 card observations + 955 TLS offers.** These are
primitive occurrences, including repeated components and configured policy
capabilities, not unique assets or vulnerabilities.

| Card tier | Version 0.2 | Version 0.3 |
|---|---:|---:|
| critical | 238 | 238 |
| medium | 203 | 274 |
| resilient | 60 | 98 |
| unknown | 118 | 9 |

The 109 resolved cases use the new context/model rules, rather than changed
input files. Of the nine remaining cases, five are HMAC-SHA-256, three are
PBKDF2-HMAC-SHA-256 and one is a SHA-256 component in RSA-OAEP. Eight need
secret/parameter review; RSA-OAEP needs a dedicated hash-construction rule.
The RSA component is independently inventoried as critical.

610 of 619 non-offered observations are rated: **98.5% classification coverage**,
not detection accuracy. The exposure index is 61.5/100. Its change reflects
policy coverage and component weighting, not remediation or lower real risk.
The hash target and generic query assumptions are documented in POLICY.md.

Version 0.2 had already expanded the source primitive-set checks from 18/24
files in the initial 0.1 run to 24/24, added full KMS KeySpec coverage, five
ELB policies and the PCAP. Version 0.3 preserves that detection coverage and
adds explicit contextual assessment and a local interactive workflow.

## Interface checks

The standalone report and app JavaScript were exercised in jsdom against the
real local HTTP service. Search, tier/scope/evidence filters, pagination,
evidence dialogs, nine review cases, 97 session rows, seven selected hybrid
rows, PT/EN interface labels and JSON export passed. The report requested no
external resources. App checks ran the challenge twice, compared identical
results (1574 unchanged, zero added/removed/reclassified), uploaded a new
Python file and recovered three history entries without script errors.

Visual layout was not verified in a real browser: the available headless-browser
download returned an invalid archive. Responsive CSS and dialog placement in
an expanded iframe are implemented, but should be checked on the presentation
computer. Windows command launchers were not executed in this Linux environment.
Pedro's earlier 0.2 scan on Windows confirmed Python 3.14.7 and TShark availability;
that is not a native Windows verification of the new 0.3 app.

## Scope and limits

- No exhaustive occurrence recall, production coverage, official scoring labels
  or calibrated security probability. Primitive-set checks are narrower than
  full cryptographic discovery.
- Python uses ASTs and bounded constants/observed calls. Java/Go use scoped
  patterns. General types, aliases, wrappers and unseen callers remain unresolved.
  Inferred sizes are conditional on the supported observed call sites.
- Unknown Python key-object operations can be missed. A Go password-derivation
  loop is inventoried as HMAC calls, not automatically inferred as PBKDF2.
- Cloud configuration describes permitted options, not actual negotiated use.
  AWS mappings cover five policy names checked on 2026-10-10; unknown names
  remain partial. KMS SYMMETRIC_DEFAULT is region-specific.
- Capture inspection covers supported TLS handshake fields, not SSH or all
  application traffic. This capture does not establish complete certificate,
  authentication or implementation visibility. Hybrid selection does not
  certify a whole session.
- Hash tiers use an explicit project extension in an ideal query model, not
  NIST-assigned risk levels or practical attack estimates. AES-128 medium
  follows the brief, not a claim of a current practical break.
- Custom inventory JSON is not a schema-validated CycloneDX CBOM. The exposure
  index is affected by repeated observations; unknowns/offers are excluded.
- TShark and cryptography are optional external components. Missing TShark
  makes captures partial; missing cryptography affects PEM/DER parsing, not
  the provided cloud JSON. Raw private keys are skipped.
- SQLite stores generated reports, not uploaded raw source/capture files.
  The loopback API is a local demo, not an internet service or hostile-file sandbox.
  History lists the latest 200 reports; comparison detail lists show up to 100
  changes per group while their counts include the full comparison.

## Reproduce

```bash
python3 -m quantumtrace doctor
python3 run_demo.py
python3 -m unittest discover -s tests -v
python3 -m quantumtrace serve
```

Use `py -3` on Windows. The core, API and history use no paid services.

## Version 0.3.1 UI correction

The embedded report now permits reference links to open a separate unsandboxed tab, while its own scripts retain an opaque origin. Launch-token removal preserves the per-tab stored session and does not change API authorization. Classification policy and data are unchanged. The provided Windows screenshots show the 0.3 app and the challenge scan working; they do not verify every UI action. The correction is checked through DOM/session tests against the real local API. External-tab opening and final Windows appearance still require confirmation in a native browser.

## Version 0.3.2 history controls

HTTP tests cover persistent individual deletion, clearing 202 saved reports
despite the 200-entry display limit, a fresh scan after clearing, authentication
and rejection while a scan is running. UI checks in jsdom against the real API
cover confirmation/cancellation, PT/EN labels, clearing the current report and
comparison, and empty history after reloading. Native confirmation dialogs and
final Windows appearance still need checking on the presentation computer.


## Version 0.3.3 priorities and presentation freeze

The 86-test suite passed in the preparation environment. Twelve added semantic
checks cover selected/configured/static ordering, offered-only inventory,
hybrid component handling, missing AES parameters, hash-model limits, resource
and session grouping, complete evidence references, deterministic ordering,
empty input, mixed evidence states and legacy rendering without report mutation.

The challenge was rescanned with unchanged totals and index: 1574 observations,
619 non-offered, 955 offers, tiers 238/274/98/9 and 61.5. The priority view contains
137 file/resource/session groups: 25 file groups, 15 AWS resource groups and
97 TLS sessions. Seven groups have selected hybrid construction-review actions.
These are technical grouping units, not a count of unique enterprise assets.
The eight additional developer fixtures still match all manual expectations
and produce nine observations with an index of 37.5.

jsdom checks against the real local API passed new priority search, action
filtering, pagination, supporting-evidence dialogs, seven hybrid groups,
PT/EN labels and a short visible policy with expandable technical detail.
History, deletion, session handling and JSON export passed with no script errors.
Standalone report checks made no external resource requests. This remains a
DOM/HTTP verification, not a native Windows/browser visual validation.

Hash tiers were reviewed against the explicit project model and cited primary
sources. No classification mapping or target changed. Hybrid explanations and
recommendations now state that a critical classical component does not prove
combined hybrid vulnerability. The final ZIP is a frozen rehearsal copy;
organiser data bytes remain unchanged.
