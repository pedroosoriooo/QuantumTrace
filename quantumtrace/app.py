"""Loopback-only UI and JSON API; uploads are inspected, never executed."""

import base64
import binascii
import hashlib
import json
import secrets
import sqlite3
import tempfile
import threading
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from . import __version__
from .inventory import MAX_FILE_BYTES, MAX_FILES, scan_path
from .report import render_html
from .runtime import diagnostics

WEB = Path(__file__).with_name("web")
MAX_TOTAL_BYTES = 80 * 1024 * 1024
MAX_BODY_BYTES = 112 * 1024 * 1024


def safe_name(value):
    if not isinstance(value, str) or not value or len(value) > 1000:
        raise ValueError("Nome de ficheiro inválido.")
    if "\\" in value or ":" in value or any(ord(c) < 32 for c in value):
        raise ValueError("O nome deve ser um caminho relativo, sem caracteres de controlo.")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("O nome deve ser um caminho relativo dentro da seleção.")
    return path


def fingerprint(report):
    files = sorted((f["source"], f.get("sha256")) for f in report["files"] if f.get("sha256"))
    return hashlib.sha256(json.dumps(files, separators=(",", ":")).encode()).hexdigest()


def finding_key(f):
    # Compare evidence, not generated IDs, timestamps or policy commentary.
    c = f.get("context") or {}
    identity_context = {k: c[k] for k in ("mechanism", "session", "event", "cipher_suite", "asset_id", "security_policy", "operation") if k in c}
    return json.dumps([f["evidence"]["source"], f["evidence"]["locator"], f["algorithm"],
                       f["key_bits"], f["role"], f["observation"], identity_context], sort_keys=True)


def compare_reports(before, after):
    a = {finding_key(f): f for f in before["findings"]}
    b = {finding_key(f): f for f in after["findings"]}
    shared = a.keys() & b.keys()
    changed = [b[k] for k in sorted(shared) if a[k]["risk"] != b[k]["risk"]]
    same_policy = before["policy"]["name"] == after["policy"]["name"]
    same_inputs = fingerprint(before) == fingerprint(after)
    same_coverage = sorted((f["source"], f["status"]) for f in before["files"]) == sorted((f["source"], f["status"]) for f in after["files"])
    return {"same_policy": same_policy, "same_supported_inputs": same_inputs, "same_file_coverage": same_coverage,
            "added_count": len(b.keys() - a.keys()), "removed_count": len(a.keys() - b.keys()),
            "reclassified_count": len(changed), "unchanged_count": len(shared) - len(changed),
            "added": [b[k] for k in sorted(b.keys() - a.keys())][:100],
            "removed": [a[k] for k in sorted(a.keys() - b.keys())][:100], "reclassified": changed[:100],
            "risk_delta": {tier: after["summary"]["risk_counts"].get(tier, 0) - before["summary"]["risk_counts"].get(tier, 0)
                           for tier in ("critical", "medium", "resilient", "unknown")},
            "score_delta": round(after["summary"]["quantum_risk_score"] - before["summary"]["quantum_risk_score"], 1)
                           if same_policy and same_inputs and same_coverage and before["summary"]["quantum_risk_score"] is not None and after["summary"]["quantum_risk_score"] is not None else None}


class History:
    def __init__(self, directory):
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / "history.sqlite3"
        with sqlite3.connect(self.path) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, label TEXT NOT NULL, origin TEXT NOT NULL, report TEXT NOT NULL)")

    def save(self, report, label, origin):
        run_id = secrets.token_hex(12)
        with sqlite3.connect(self.path) as conn:
            conn.execute("INSERT INTO runs VALUES (?, ?, ?, ?, ?)",
                         (run_id, report["generated_at"], label, origin, json.dumps(report, ensure_ascii=False)))
        return run_id

    def list(self):
        with sqlite3.connect(self.path) as conn:
            records = conn.execute("SELECT id, created_at, label, origin, report FROM runs ORDER BY created_at DESC LIMIT 200").fetchall()
        return [{"id": r[0], "created_at": r[1], "label": r[2], "origin": r[3],
                 "summary": json.loads(r[4])["summary"], "policy": json.loads(r[4])["policy"]["name"]} for r in records]

    def get(self, run_id):
        with sqlite3.connect(self.path) as conn:
            record = conn.execute("SELECT report FROM runs WHERE id = ?", (run_id,)).fetchone()
        if not record:
            raise KeyError(run_id)
        return json.loads(record[0])

    def delete(self, run_id):
        with sqlite3.connect(self.path) as conn:
            deleted = conn.execute("DELETE FROM runs WHERE id = ?", (run_id,)).rowcount
            if not deleted:
                raise KeyError(run_id)
        return deleted

    def clear(self):
        with sqlite3.connect(self.path) as conn:
            return conn.execute("DELETE FROM runs").rowcount


class Application:
    def __init__(self, project_root, state_directory=None):
        self.project_root = Path(project_root)
        self.history = History(Path(state_directory) if state_directory else self.project_root / ".quantumtrace")
        self.token = secrets.token_urlsafe(32)
        self.jobs = {}
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="quantumtrace-scan")

    def submit(self, request):
        if not isinstance(request, dict):
            raise ValueError("O pedido deve ser um objeto JSON.")
        origin = request.get("source")
        label = request.get("label") or ("Dados do desafio" if origin == "demo" else "Ficheiros selecionados")
        if not isinstance(label, str) or len(label) > 120:
            raise ValueError("O nome da análise deve ter até 120 caracteres.")
        with self.lock:
            if any(j["status"] in {"queued", "running"} for j in self.jobs.values()):
                raise RuntimeError("Já existe uma análise em curso. Aguarda a conclusão.")
            workspace = None
            try:
                if origin == "demo":
                    target = self.project_root / "data"
                    if not target.is_dir():
                        raise ValueError("A pasta data não foi encontrada. Extrai todo o projeto antes de iniciar a app.")
                elif origin == "upload":
                    entries = request.get("files")
                    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_FILES:
                        raise ValueError(f"Seleciona entre 1 e {MAX_FILES} ficheiros.")
                    workspace = tempfile.TemporaryDirectory(prefix="quantumtrace-upload-")
                    target = Path(workspace.name)
                    names, total = set(), 0
                    for entry in entries:
                        if not isinstance(entry, dict):
                            raise ValueError("Entrada de ficheiro inválida.")
                        name = safe_name(entry.get("name")).as_posix()
                        if name in names:
                            raise ValueError("Há caminhos duplicados na seleção. Seleciona a pasta para preservar a estrutura.")
                        names.add(name)
                        encoded = entry.get("data")
                        if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_FILE_BYTES + 2) // 3):
                            raise ValueError("Cada ficheiro pode ter até 20 MiB.")
                        try:
                            raw = base64.b64decode(encoded, validate=True)
                        except (ValueError, binascii.Error) as exc:
                            raise ValueError("Conteúdo de ficheiro inválido.") from exc
                        total += len(raw)
                        if len(raw) > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                            raise ValueError("Limite: 20 MiB por ficheiro e 80 MiB por seleção.")
                        destination = target / name
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        destination.write_bytes(raw)
                else:
                    raise ValueError("Escolhe os dados do desafio ou envia ficheiros.")
                job_id = secrets.token_hex(12)
                self.jobs[job_id] = {"id": job_id, "status": "queued", "label": label,
                                     "created_at": datetime.now(timezone.utc).isoformat()}
                self.executor.submit(self._analyse, job_id, target, workspace, label, origin)
                return dict(self.jobs[job_id])
            except BaseException:
                if workspace:
                    workspace.cleanup()
                raise

    def _analyse(self, job_id, target, workspace, label, origin):
        try:
            with self.lock:
                self.jobs[job_id]["status"] = "running"
            report = scan_path(target)
            run_id = self.history.save(report, label.strip() or "Análise", origin)
            with self.lock:
                self.jobs[job_id].update(status="completed", run_id=run_id, summary=report["summary"])
        except Exception as exc:
            # Do not echo uploaded source or tool stderr in an error response.
            with self.lock:
                self.jobs[job_id].update(status="failed", error=f"Não foi possível concluir a análise ({type(exc).__name__}). Tenta novamente e consulta a cobertura dos ficheiros.")
        finally:
            if workspace:
                workspace.cleanup()

    def job(self, job_id):
        with self.lock:
            return dict(self.jobs[job_id])

    def delete_history(self, run_id=None):
        # Keep submission and deletion mutually exclusive. A running scan must
        # finish before its report can be removed from history.
        with self.lock:
            if any(j["status"] in {"queued", "running"} for j in self.jobs.values()):
                raise RuntimeError("Aguarda a conclusão da análise antes de apagar o histórico.")
            return self.history.clear() if run_id is None else self.history.delete(run_id)

    def close(self):
        self.executor.shutdown(wait=True)


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = "QuantumTrace/" + __version__

        def log_message(self, *args):
            pass

        def send(self, status, payload, content_type="application/json; charset=utf-8", disposition=None):
            body = json.dumps(payload, ensure_ascii=False).encode() if isinstance(payload, (dict, list)) else payload
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-src 'self' about:; object-src 'none'; base-uri 'none'; frame-ancestors 'self'")
            if disposition:
                self.send_header("Content-Disposition", disposition)
            self.end_headers()
            self.wfile.write(body)

        def allowed_host(self):
            return self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}"

        def authorised(self):
            origin = self.headers.get("Origin")
            expected = f"http://127.0.0.1:{self.server.server_port}"
            token = self.headers.get("X-QuantumTrace-Token", "")
            return (token.isascii() and self.allowed_host() and (not origin or origin == expected)
                    and secrets.compare_digest(token, app.token))

        def do_GET(self):
            path = urlsplit(self.path).path
            if not self.allowed_host():
                return self.send(403, {"error": "Host inválido."})
            if path.startswith("/api/"):
                if not self.authorised():
                    return self.send(403, {"error": "Sessão inválida. Reabre a app a partir do terminal."})
                try:
                    if path == "/api/status":
                        return self.send(200, {"version": __version__, "dependencies": diagnostics(),
                                               "demo_available": (app.project_root / "data").is_dir(),
                                               "limits": {"file_bytes": MAX_FILE_BYTES, "total_bytes": MAX_TOTAL_BYTES, "files": MAX_FILES}})
                    if path == "/api/runs":
                        return self.send(200, {"runs": app.history.list()})
                    parts = path.strip("/").split("/")
                    if len(parts) == 3 and parts[:2] == ["api", "jobs"]:
                        return self.send(200, app.job(parts[2]))
                    if len(parts) in {3, 4} and parts[:2] == ["api", "runs"]:
                        report = app.history.get(parts[2])
                        if len(parts) == 3 or parts[3] == "json":
                            return self.send(200, report)
                        if parts[3] == "html":
                            return self.send(200, render_html(report, embedded=True).encode(), "text/html; charset=utf-8")
                        if parts[3] == "download":
                            return self.send(200, render_html(report).encode(), "text/html; charset=utf-8", 'attachment; filename="QuantumTrace-report.html"')
                except KeyError:
                    return self.send(404, {"error": "Análise não encontrada."})
                return self.send(404, {"error": "Recurso não encontrado."})
            assets = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"), "/app.css": ("app.css", "text/css")}
            if path in assets:
                name, content_type = assets[path]
                return self.send(200, (WEB / name).read_bytes(), content_type + "; charset=utf-8")
            return self.send(404, {"error": "Recurso não encontrado."})

        def do_POST(self):
            if not self.authorised():
                return self.send(403, {"error": "Sessão inválida. Reabre a app a partir do terminal."})
            try:
                if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                    return self.send(415, {"error": "Utiliza application/json."})
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= MAX_BODY_BYTES:
                    return self.send(413, {"error": "O pedido excede o limite de envio."})
                self.connection.settimeout(30)
                request = json.loads(self.rfile.read(length))
                path = urlsplit(self.path).path
                if path == "/api/analyses":
                    return self.send(202, app.submit(request))
                if path == "/api/compare" and isinstance(request, dict):
                    if not all(isinstance(request.get(k), str) for k in ("before", "after")):
                        raise ValueError("Seleciona duas análises válidas para comparar.")
                    return self.send(200, compare_reports(app.history.get(request.get("before")), app.history.get(request.get("after"))))
                return self.send(404, {"error": "Recurso não encontrado."})
            except RuntimeError as exc:
                return self.send(409, {"error": str(exc)})
            except KeyError:
                return self.send(404, {"error": "Análise não encontrada."})
            except (ValueError, UnicodeError, OSError) as exc:
                message = str(exc) if isinstance(exc, ValueError) and not isinstance(exc, json.JSONDecodeError) else "Pedido inválido. Verifica os ficheiros e tenta novamente."
                return self.send(400, {"error": message})

        def do_DELETE(self):
            if not self.authorised():
                return self.send(403, {"error": "Sessão inválida. Reabre a app a partir do terminal."})
            path = urlsplit(self.path).path
            parts = path.strip("/").split("/")
            try:
                if path == "/api/runs":
                    return self.send(200, {"deleted_count": app.delete_history()})
                if len(parts) == 3 and parts[:2] == ["api", "runs"]:
                    return self.send(200, {"deleted_count": app.delete_history(parts[2])})
                return self.send(404, {"error": "Recurso não encontrado."})
            except RuntimeError as exc:
                return self.send(409, {"error": str(exc)})
            except KeyError:
                return self.send(404, {"error": "Análise não encontrada."})
            except (OSError, sqlite3.Error):
                return self.send(500, {"error": "Não foi possível atualizar o histórico. Tenta novamente."})

    return Handler


def serve(project_root, port=8765, open_browser=True, state_directory=None):
    app = Application(project_root, state_directory)
    try:
        try:
            server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app))
        except OSError:
            if port == 0:
                raise
            server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(app))
        server.daemon_threads = True
        url = f"http://127.0.0.1:{server.server_port}/#token={app.token}"
        print(f"QuantumTrace {__version__} — app local\n{url}\nMantém esta janela aberta. Ctrl+C para terminar.", flush=True)
        if open_browser:
            webbrowser.open(url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nQuantumTrace terminou. O histórico ficou guardado.")
        finally:
            server.server_close()
    finally:
        app.close()
    return 0
