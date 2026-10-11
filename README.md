# QuantumTrace — Hidden Signal

Evidence-based cryptographic discovery and post-quantum readiness assessment.
Version 0.3.3, validated against the partner starter during JunctionX Lisbon 2026.

## JunctionX Lisbon 2026 submission — v0.3.3

Built by **Hidden Signal**. This repository contains the final local app,
source code, 86 automated tests, documented assessment policy, synthetic
challenge inputs, synthetic examples and reproducible reports.

**Start on Windows:** download the repository ZIP, extract it, then open
`INICIAR_APP.cmd` in the project folder. Python 3.10+ is required. Install
Wireshark/TShark for PCAP inspection; JSON and supported source scans work
without it.

**Start on Linux/macOS:** `python3 -m quantumtrace serve`.

**Reproduce the challenge run:** `python3 run_demo.py`.
**Run the tests:** `python3 -m unittest discover -s tests -v`.

[Validation and limits](VALIDATION.md)

The project runs locally; this repository URL provides the source and
downloadable demo, rather than a hosted scanning service. The runtime uses
explicit rules and requires no LLM or paid API. Development was AI-assisted.

---



## Explore the hosted demo

[Open QuantumTrace Demo](https://quantumtrace-hidden-signal.plumfrog.chatgpt.site) to inspect saved real audit reports and the 50-second illustrated video. The AES examples were scanned separately on synthetic inputs. New file and folder scans run in the local app.

## Open the local app

Extract the complete release ZIP. On Windows, open `INICIAR_APP.cmd` inside
the extracted `quantumtrace` directory. It opens the browser and runs a local
server; keep its terminal window open. Python 3.10+ is required. No pip install
is needed for the app, JSON API or SQLite history.

On Linux/macOS, from the extracted project directory:

```bash
python3 -m quantumtrace serve
```

The app offers file/folder selection, fresh scans of the challenge data,
persistent history with individual deletion and full clearing, comparison,
inspectable review cases and HTML/JSON export.
Portuguese and English UI labels are available; original evidence and technical
assessment explanations remain in English. Loading a saved run does not scan
the inputs again. Two identical runs normally have identical observations.
History stores reports in `.quantumtrace/history.sqlite3`; uploaded raw files
are temporary and removed after analysis. The reports contain filenames,
locators and recognised crypto evidence, so treat exports as project data.

The API binds to `127.0.0.1` only. The browser uses a per-launch session token,
and foreign origins are rejected. No cloud hosting, AWS account or LLM is
required. See `APP_API.md` for endpoints and `QUICKSTART_PT.md` for Windows steps.

## Run the synthetic demo

Python 3.10+ is required. The core has no third-party dependencies and makes no
paid API calls. From the extracted project directory:

```bash
python3 -m quantumtrace scan samples --out reports
```

On Windows, use `py` instead of `python3` when appropriate:

```powershell
py -m quantumtrace scan samples --out reports
```

Open `reports/report.html` in a browser. The report works offline and includes
search, risk/evidence filters, reasoning, source locations, input coverage and
a JSON download. `reports/report.json` is the machine-readable inventory.

The bundled `samples/` files are **synthetic demonstration fixtures**, not the
partner dataset. Results on these files are not a measured challenge accuracy.

## Scan partner data

Place data in a separate `data/` directory and run:

```bash
python3 -m quantumtrace scan data --out reports
python3 -m quantumtrace doctor
```

The input is read passively. Source code is parsed, never executed. Do not put
generated report files inside the input directory except the excluded
`reports/` directory. Direct symlink inputs and symlink files are skipped/rejected.

Optional certificate dependency:

```bash
python3 -m pip install "cryptography>=42"
```

PCAP/PCAPNG inspection requires a locally installed TShark (from Wireshark)
available on PATH, or in the standard Windows Wireshark installation directory.
An absent TShark is reported as **partial**, never as safe.
No live network probing is implemented. TShark reads local captures only.
Alternatively, provide a TShark `-T json` export, or the documented normalised
TLS fixture format in `samples/tls.json`.

## Current coverage

| Input | Detector | Evidence status | Limits |
|---|---|---|---|
| JSON configurations | Known crypto field names and algorithm labels | configured | Known generic fields plus AWS KMS/ELB mappings; other schemas may be missed |
| Python source | AST calls and imported namespaces | static-call | Selected APIs, constants and observed call sites; general data flow/alias rebinding unresolved |
| Java source | Selected standard crypto API patterns | static-call | Scoped patterns and constant/key-size inference; no semantic type resolution |
| Go source | Selected crypto API call patterns | static-call | Known crypto imports and aliases, selected helper key-length inference; general wrappers unsupported |
| PEM/DER certificate/public key | Optional `cryptography` parsing | key-material / certificate-signature | Limited key types and signature OIDs; private keys deliberately skipped |
| Normalised TLS or TShark JSON | Handshake event extraction | offered / negotiated | Limited IDs; ambiguous multi-handshake packets deliberately skipped |
| PCAP/PCAPNG | Optional TShark adapter | offered / negotiated | Validated on supplied synthetic PCAP with TShark 4.2.2; only supported TLS fields |

Other file types (including arbitrary binaries) are reported as unsupported.
No training, cloud account or LLM is required for this baseline. There is no
LLM inference component in version 0.3: classifications come from explicit,
inspectable rules. AI-assisted development is permitted by the event rules.

## What the result means

The scanner inventories **primitives**, not certified secure systems.

* `configured`: a recognised field declares a primitive; not proof of use.
* `static-call`: syntactic evidence of a call; not proof the call ran.
* `offered`: an option in ClientHello; not proof it was selected.
* `negotiated`: a selected mechanism in an observed handshake event.
* `key-material`: a parsed public key, not copied into the report.
* `certificate-signature`: the issuer signature, distinct from the subject key.

Every finding has a file SHA-256, locator, detector, evidence, role, confidence,
classification explanation and documentation references. Confidence is a
qualitative evidence label, **not a calibrated probability**.

The challenge policy rates classical public-key primitives critical, AES-128
and legacy symmetric/hash primitives medium, AES-256 and recognised final PQC
families resilient. Unknown AES sizes remain unknown. Legacy names such as
Kyber are not automatically treated as conformance to the final ML-KEM standard.
Version 0.3 extends the challenge brief with a documented, context-aware hash
policy. Its primitive-level target is 128 bits in an ideal generic quantum
query model: collision `n/3`, preimage `n/2`. Signature digests use the collision
model. TLS suite hashes use it as an explicitly conservative component policy,
without separately claiming an HKDF/MAC assessment. Unspecified SHA-384/512
uses meet this target even in the weaker collision model; SHA-256 with unknown
purpose stays unresolved. These exponents are neither practical attack costs
nor NIST security categories. See `POLICY.md` for rules and assumptions.

The exact IETF ChaCha20 TLS suite establishes a 256-bit encryption key; a bare
ChaCha20 name does not. HMAC key entropy/tag parameters and PBKDF2 password
entropy remain unresolved when not established. PBKDF2 output length is never
treated as password entropy. Known constructions outside these hash rules
(currently RSA-OAEP) remain explicit policy gaps.

AES-128 is not asserted to be currently broken: this tier follows the challenge
brief. The NIST guidance discusses practical constraints on Grover attacks.
Similarly, a PQC label does not prove a correct implementation or a fully
protected surrounding protocol.

The exposure index is the mean of `critical=100`, `medium=50`, `resilient=0`
over rated non-offered findings. Unknown findings are excluded and displayed.
An empty inventory has a **null** index, not zero. A low index is not a security
claim. Repeated assets and component counts affect this simple heuristic.
Classical components in hybrid KEMs retain their own classification; this must
not be read as a finding that the combined hybrid mechanism is broken.

## Inventory format

The JSON is a **custom CBOM inventory** with schema identifier
`quantumtrace.inventory/1.0`. It is NOT a validated CycloneDX document.
The brief allows custom JSON. A standards-compliant CycloneDX exporter remains
future work and must be schema-validated before being advertised as compliant.

Top-level fields are `schema`, `tool`, `version`, `generated_at`, `policy`,
`summary`, `files`, `findings`, and `warnings`. Each finding carries evidence
and policy details. Refer to `reports/report.json` for a full generated example.

## Verification

```bash
python3 -m unittest discover -s tests -v
```

Behavioral tests cover false positives from comments/strings, unknown sizes,
PQC names versus classical DSA, offers versus negotiated choices, TLS hybrid
components, unsupported identifiers, missing TShark, malformed files, passive
source inspection, private-key handling and safe HTML embedding.

These tests check behavior, not general discovery recall or challenge accuracy.
Version 0.3 checks manually defined expectations for all 24 partner source files,
six AES key-size examples, 10 KMS keys, five TLS policies and the synthetic PCAP.
It also exercises the real HTTP upload/scan/history/comparison flow. See
VALIDATION.md. These checks are not official scoring labels or exhaustive
occurrence recall.

Optional CI-friendly flags:

```bash
python3 -m quantumtrace scan data --out reports --strict --fail-on-critical
```

Exit codes: 0 completed, 1 critical primitive found with the flag enabled,
2 input/output failure or incomplete analysis with `--strict`.
Input limits: 20 MiB per file, 2,000 files, 45 seconds per TShark invocation.
This prototype is not a hardened sandbox for hostile capture files.

## Documentation and sources

* Challenge brief: `Inspiring Solutions - JunctionX Lisbon 2026.pdf` supplied at the event.
* [NIST PQC FAQ](https://csrc.nist.gov/projects/post-quantum-cryptography/faqs)
* [ML-KEM / FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
* [ML-DSA / FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
* [SLH-DSA / FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)
* [TLS 1.3 / RFC 8446](https://www.rfc-editor.org/info/rfc8446/)
* [IANA TLS registries](https://www.iana.org/assignments/tls-parameters)
* [Wireshark TLS fields](https://www.wireshark.org/docs/dfref/t/tls.html)
* [TShark](https://www.wireshark.org/docs/man-pages/tshark.html)
* [Python AST](https://docs.python.org/3/library/ast.html)
* [cryptography X.509](https://cryptography.io/en/latest/x509/reference/)
* [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/)

Source code is MIT licensed. Python standard-library modules and optional
Wireshark/TShark and `cryptography` retain their own licenses. No external
project source code has been copied into the scanner.

## Partner demo (version 0.3)

The release ZIP includes `data/` from [the partner starter](https://github.com/joaoalves3901/JunctionX-QuantumTrace), `run_demo.py` and a precomputed `reports/` directory. Run `python3 run_demo.py`, or `py run_demo.py` on Windows. Read `QUICKSTART_PT.md` for setup. TShark remains an optional external dependency, not bundled.

AWS mappings were checked on 2026-10-10 against [KMS CreateKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html), [ALB security policies](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html) and [NLB security policies](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html). Unknown policies remain partial. KMS `SYMMETRIC_DEFAULT` is interpreted only with a recognised region; China-region SM4 is not labelled AES.

Source key sizes inferred through helper calls describe supported observed call
sites, not every possible invocation. HMAC and PBKDF2 are discovered but remain
unresolved without sufficient secret-generation/context parameters. The custom
PBKDF2-style Go loop is inventoried as HMAC calls, not automatically labelled
PBKDF2. The report distinguishes missing parameters, missing context and policy
coverage gaps.

The HTML report paginates observations and groups TLS selections into sessions with packet locators. Counts represent observations, including repeated primitives and permitted suites, not deduplicated enterprise assets.

On the unchanged supplied dataset: **1574 observations = 619 card observations
+ 955 TLS offers**. Card tiers are 238 critical, 274 medium, 98 resilient and
9 requiring review. Of those 9, eight lack parameters and one requires an
RSA-OAEP hash-construction rule. 98.5% classification coverage refers only to
the 619 non-offered observations; it is **not measured accuracy**. Changing
assessment rules changes the exposure index, without changing the input data.

## Version 0.3.1 UI correction

Reference links inside the embedded report can open a new tab. Reference links are underlined and show their destination on hover. After the launch token is stored in tab session storage, it is removed from the address bar; refreshing the same tab preserves the session. Input selection uses Choose files / Choose folder and Analyse selection. No launcher edit is needed. Assessment rules and observations are unchanged.

## Version 0.3.2 history controls

Each history entry has a Delete button, and Clear history removes all saved
analyses. Both actions require confirmation and are disabled during a scan.
Deleting the displayed analysis clears its report view; deleting a comparison
input clears the comparison. Original inputs and downloaded exports are kept.
The authenticated DELETE API persists removal across restarts, and clearing
history covers entries beyond the latest 200 shown in the interface.


## Version 0.3.3: evidence-aware priorities and release freeze

The report groups observations by source file, AWS resource identifier, or TLS
session. Each group shows mechanisms, evidence states, reason, next step and
links to supporting observations. Search, action filters and six-group pages
keep the summary manageable. The JSON adds `priorities` with method
`quantumtrace.technical-inspection/1.0`; it is additive to the existing schema.

The inspection order considers selected classical public-key mechanisms before
configured ones and static calls. Offered capabilities remain inventory-only.
Hybrid groups receive a construction-review action; their classical component's
critical tier is not proof that the combined hybrid is broken. Hash model checks
are labelled as project policy, with no NIST-category or practical-break claim.
The visible policy is shorter and its complete technical object remains expandable.

This is technical inspection guidance, not a complete business-risk ranking.
Ownership, impact and confidentiality lifetime still require enterprise context.
Old HTML views can derive this summary from saved observations without rescanning
or changing the saved score. Old JSON exports retain their original structure.

The 0.3.3 release is frozen for presentation rehearsal on 2026-10-10. The organiser
inputs and classification rules are preserved: 1574 observations, 619 cards,
955 offers, nine unresolved cases and index 61.5. Only a demonstrated defect
should justify another release before the presentation.
