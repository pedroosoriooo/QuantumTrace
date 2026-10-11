# QuantumTrace 0.3 — local JSON API

Start `python3 -m quantumtrace serve --no-browser` (Windows: `py -3` instead of
`python3`). The terminal prints a loopback URL with a per-launch session token
in its fragment. The port defaults to 8765, or an available port if occupied.
No extra dependency, cloud service or agent is required.

Requests must use the printed `http://127.0.0.1:PORT` address and send the token
as the `X-QuantumTrace-Token` header. Keep it private. JSON POST requests also
send `Content-Type: application/json`. The service accepts its own origin;
it does not advertise permissive CORS. It is a local demo, not a production
internet service.

| Endpoint | Behavior |
|---|---|
| `GET /api/status` | Tool version, optional dependency availability and upload limits |
| `POST /api/analyses` | Start an asynchronous analysis; returns 202 and a job ID |
| `GET /api/jobs/JOB_ID` | queued/running/completed/failed; completed jobs include a run ID |
| `GET /api/runs` | Latest 200 saved runs, labels and summaries |
| `GET /api/runs/RUN_ID` | Complete custom inventory JSON |
| `GET /api/runs/RUN_ID/json` | Same inventory for download/integration |
| `GET /api/runs/RUN_ID/html` | Embedded self-contained report |
| `GET /api/runs/RUN_ID/download` | Standalone offline HTML export |
| `DELETE /api/runs/RUN_ID` | Delete one saved report; returns `deleted_count: 1` |
| `DELETE /api/runs` | Delete every saved report, including entries beyond the latest 200; returns the deleted count |
| `POST /api/compare` | Compare two saved runs using evidence identity |

Challenge-data request:

```json
{"source":"demo","label":"Challenge scan"}
```

Upload request; `data` is base64 file content, `name` is its relative path:

```json
{"source":"upload","label":"New inputs","files":[{"name":"config.json","data":"eyJhbGdvcml0aG0iOiJSU0FfMjA0OCJ9"}]}
```

Comparison request:

```json
{"before":"SAVED_RUN_ID","after":"SAVED_RUN_ID"}
```

One analysis runs at a time; a concurrent submission returns 409. Invalid input
returns 400, oversized requests 413, missing session 403, unknown IDs 404.
Upload limits: 2000 files, 20 MiB per file, 80 MiB total. Absolute paths, parent
traversal, duplicate names and malformed base64 are rejected. Files are not
executed. Inputs are temporary; reports are persisted to SQLite after analysis.
Scans with partial/error files still have a report containing those statuses.

History lives at `.quantumtrace/history.sqlite3` inside the extracted project.
An alternate location can be selected with `--state-dir PATH`. Copy that file
with the app stopped if you want to preserve history when changing folders.
Opening an old report does not rerun the scan. The app does not automatically
import the precomputed report; use the challenge-data button to create its
first history entry.

The app asks for confirmation before deleting one analysis or clearing history.
Deletion removes saved reports from SQLite and persists after restarting the app.
It does not remove original input files, the bundled offline report or previously
downloaded exports. DELETE requests require the same session/origin checks as
other API requests. Deletion returns 409 while an analysis is queued or running;
wait for completion, then retry. Clearing an empty history returns a count of 0.

Comparisons report added, removed, reclassified and unchanged observations,
input-hash/policy/coverage equality and risk-tier deltas. Detailed lists are
limited to the first 100 changes per group; counts cover the full comparison.
Removal means an observation no longer appears, not proof of remediation.
The supported-input fingerprint covers successfully read source/capture/config
bytes; unsupported metadata is not treated as analysed evidence. Score deltas
are withheld when inputs, coverage or policy differ.


### Additive priority summary in 0.3.3

New report JSON contains `priorities.method`, `group_count` and `groups`.
Each group includes its source, resource kind/identifier, mechanisms, evidence
counts, non-offered risk counts and actions. Actions provide a reason, next
step, evidence state and supporting `finding_ids`. `inspection_order` is a
technical sorting key, not a score or calibrated business priority.
Existing endpoints and finding identities are unchanged. Rendering an older
saved report derives this view if absent; its original JSON and score are not
modified and its input files are not reanalysed.
