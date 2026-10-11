"""Common evidence model and orchestration; no scanned code is executed."""

import hashlib
import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .policy import classify

SUPPORTED = {".json", ".py", ".java", ".go", ".pem", ".crt", ".cer", ".der", ".pcap", ".pcapng"}
SKIP_DIRS = {".git", ".venv", "venv", ".quantumtrace", "node_modules", "__pycache__", "reports"}
MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_FILES = 2000


class Collector:
    def __init__(self, source, digest):
        self.source = source
        self.digest = digest
        self.findings = []
        self.warnings = []
        self.status = "analysed"

    def warn(self, message):
        if message not in self.warnings:
            self.warnings.append(message)

    def add(self, algorithm, observation, locator, evidence, key_bits=None,
            role=None, detector="unknown", confidence="high", context=None, caveats=None):
        policy = classify(algorithm, key_bits, role, context)
        identity = json.dumps([self.source, locator, algorithm, key_bits, role, observation, context], sort_keys=True)
        item = {
            "id": "qt-" + hashlib.sha256(identity.encode()).hexdigest()[:16],
            "algorithm": algorithm, "key_bits": key_bits,
            "role": role or "unspecified", "observation": observation,
            "confidence": confidence,
            "evidence": {"source": self.source, "source_sha256": self.digest,
                         "locator": locator, "detail": evidence, "detector": detector},
            "context": context, "caveats": caveats or [], **policy,
        }
        if not any(f["id"] == item["id"] for f in self.findings):
            self.findings.append(item)


def scan_path(target):
    from .scanners import scan_certificate, scan_config, scan_python, scan_other_code
    from .tls import scan_capture, scan_tls_json

    supplied = Path(target)
    if supplied.is_symlink():
        raise ValueError("Symbolic-link inputs are not supported.")
    target = supplied.resolve()
    if not target.exists():
        raise ValueError("Input path does not exist.")
    if target.is_symlink():
        raise ValueError("Symbolic-link inputs are not supported.")
    started = time.perf_counter()
    paths = [target] if target.is_file() else sorted(
        p for p in target.rglob("*") if p.is_file() and not p.is_symlink()
        and not any(part in SKIP_DIRS for part in p.relative_to(target).parts)
    )
    findings, files, warnings = [], [], []
    if len(paths) > MAX_FILES:
        warnings.append({"source": ".", "message": f"File limit reached: processing the first {MAX_FILES} files only."})
        paths = paths[:MAX_FILES]
    for path in paths:
        name = path.name if target.is_file() else path.relative_to(target).as_posix()
        suffix = path.suffix.lower()
        if suffix not in SUPPORTED:
            files.append({"source": name, "status": "unsupported", "findings": 0})
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                raise ValueError("File exceeds the 20 MiB input limit.")
            raw = path.read_bytes()
            c = Collector(name, hashlib.sha256(raw).hexdigest())
            if suffix == ".json":
                data = json.loads(raw.decode("utf-8-sig"))
                if scan_tls_json(data, c):
                    kind = "tls-export"
                else:
                    scan_config(data, c)
                    kind = "configuration"
            elif suffix == ".py":
                scan_python(raw.decode("utf-8-sig"), c)
                kind = "python-code"
            elif suffix in {".java", ".go"}:
                scan_other_code(raw.decode("utf-8-sig"), c, suffix)
                kind = "java-code" if suffix == ".java" else "go-code"
            elif suffix in {".pcap", ".pcapng"}:
                scan_capture(path, c)
                kind = "packet-capture"
            else:
                scan_certificate(raw, c)
                kind = "certificate-or-public-key"
            findings.extend(c.findings)
            warnings.extend({"source": name, "message": w} for w in c.warnings)
            files.append({"source": name, "status": c.status, "kind": kind, "sha256": c.digest, "findings": len(c.findings)})
        except (ValueError, UnicodeError, OSError, RecursionError) as exc:
            files.append({"source": name, "status": "error", "findings": 0})
            # JSON decode errors sometimes include input snippets. Only expose
            # the error type; logs must not echo unknown sensitive input.
            warnings.append({"source": name, "message": f"Could not analyse file ({type(exc).__name__})."})
    findings.sort(key=lambda f: (f["evidence"]["source"], str(f["evidence"]["locator"]), f["algorithm"]))
    return make_report(findings, files, warnings, time.perf_counter() - started)


def build_priorities(findings):
    """Technical inspection order, grouped by source and observed resource.

    This deliberately has no business-impact score. Offered capabilities never
    create a migration action; hybrid components receive construction review.
    """
    evidence_order = {"negotiated": 0, "configured": 1, "key-material": 2,
                      "certificate-signature": 2, "static-call": 3}
    groups = {}
    for f in findings:
        source = f["evidence"]["source"]
        context = f.get("context") or {}
        resource_kind = "tls-session" if context.get("session") is not None else "cloud-resource" if context.get("asset_id") else "file"
        resource = str(context.get("session")) if resource_kind == "tls-session" else str(context.get("asset_id")) if resource_kind == "cloud-resource" else source
        key = (source, resource_kind, resource)
        group = groups.setdefault(key, {"source": source, "resource_kind": resource_kind,
                                       "resource": resource, "findings": []})
        group["findings"].append(f)
    result = []
    for key, group in groups.items():
        items = sorted(group.pop("findings"), key=lambda f: f["id"])
        eligible = [f for f in items if f["observation"] != "offered"]
        actions = {}
        for f in eligible:
            state = f["observation"]
            hybrid = bool((f.get("context") or {}).get("hybrid_components"))
            if hybrid:
                kind, rank = "hybrid-review", 4
                title = "Review the hybrid construction"
                reason = "Component tiers do not determine the security of the combined hybrid. A critical classical component does not prove the hybrid is broken."
                next_step = "Verify the exact hybrid group, combiner, implementation and authentication. Keep the classical and PQC evidence together."
            elif f["risk"] == "critical":
                kind, rank = "public-key-migration", evidence_order.get(state, 3)
                title = "Plan public-key migration"
                reason = {"negotiated": "A classical public-key mechanism was selected in the captured handshake; complete session security is not established.",
                          "configured": "Declared configuration includes a classical public-key mechanism; actual runtime use is not established.",
                          "static-call": "A supported source call references classical public-key cryptography; runtime execution is not established.",
                          "key-material": "A classical public key was parsed; ownership, deployment and actual use need confirmation.",
                          "certificate-signature": "A certificate contains a classical signature; chain validation and deployment need confirmation."}.get(state, "A classical public-key primitive was identified; confirm its use before planning migration.")
                next_step = f["recommendation"]
            elif f["risk"] == "unknown":
                kind, rank, title = "missing-information", 5, "Resolve missing information"
                reason = "The primitive needs parameters, security context or a construction-specific assessment rule. No safe tier is inferred."
                next_step = f["recommendation"]
            elif f["risk"] == "medium":
                if f.get("classical_warning"):
                    kind, rank, title = "deprecated-review", 6, "Review deprecated cryptography"
                    reason = "This primitive also has a classical-security concern; review the actual construction and replacement."
                elif (f.get("assessment") or {}).get("rule_id") == "hash-generic-query-policy":
                    kind, rank, title = "hash-policy-review", 7, "Review the project hash model"
                    reason = "This tier uses the project's ideal query model and chosen target. It is not a NIST category or evidence of a practical attack."
                else:
                    kind, rank, title = "symmetric-policy-review", 6, "Review symmetric protection"
                    reason = "This primitive is medium under the challenge policy; practical exposure depends on usage and protection lifetime."
                next_step = f["recommendation"]
            else:
                kind, rank, title = "verify-resilient-component", 8, "Verify deployment and surrounding mechanisms"
                reason = "The primitive meets a supported resilient tier; this does not certify the resource, protocol or implementation."
                next_step = f["recommendation"]
            # Different recommendations remain visible within the same resource.
            action_key = (kind, state, next_step)
            action = actions.setdefault(action_key, {"kind": kind, "title": title,
                                                    "observation": state, "inspection_order": rank,
                                                    "reason": reason, "next_step": next_step,
                                                    "finding_ids": []})
            action["finding_ids"].append(f["id"])
        offers = [f for f in items if f["observation"] == "offered"]
        if offers:
            actions[("offered-capability", "offered", "")] = {
                "kind": "offered-capability", "title": "Inventory offered capabilities",
                "observation": "offered", "inspection_order": 9,
                "reason": "An offer is a capability advertisement, not proof of selection. Offers do not create a migration priority or enter the exposure index.",
                "next_step": "Compare with selected mechanisms and deployment policy before deciding whether a capability should be disabled.",
                "finding_ids": [f["id"] for f in offers],
            }
        ordered = sorted(actions.values(), key=lambda a: (a["inspection_order"], evidence_order.get(a["observation"], 4), a["kind"], a["next_step"]))
        mechanisms = sorted({(f["algorithm"], f.get("key_bits"), (f.get("context") or {}).get("mechanism") if (f.get("context") or {}).get("hybrid_components") else None)
                             for f in eligible}, key=lambda m: (m[0], str(m[1]), str(m[2])))
        group.update(id="qt-resource-" + hashlib.sha256(json.dumps(key).encode()).hexdigest()[:16],
                     inspection_order=ordered[0]["inspection_order"],
                     evidence_counts=dict(Counter(f["observation"] for f in items)),
                     risk_counts=dict(Counter(f["risk"] for f in eligible)),
                     mechanisms=[{"algorithm": a, "key_bits": bits, "hybrid_group": hybrid} for a, bits, hybrid in mechanisms],
                     offered_mechanisms=[{"algorithm": a, "key_bits": bits} for a, bits in sorted({(f["algorithm"], f.get("key_bits")) for f in offers}, key=lambda m: (m[0], str(m[1])))],
                     actions=ordered)
        result.append(group)
    result.sort(key=lambda g: (g["inspection_order"], g["source"], g["resource_kind"], g["resource"]))
    return {
        "method": "quantumtrace.technical-inspection/1.0",
        "description": "Technical inspection order by primitive and evidence state, not a calibrated enterprise risk ranking. Business impact, asset ownership and confidentiality lifetime are not known.",
        "ordering": "Selected classical public-key mechanisms, configured mechanisms, public-key material/certificate signatures, then static calls; hybrid review, missing information, policy reviews and deployment verification follow. Offered capabilities are inventory-only.",
        "group_count": len(result), "groups": result,
    }


def make_report(findings, files, warnings, seconds=0):
    # Offered mechanisms are inventory entries, not proof of negotiated use.
    eligible = [f for f in findings if f["observation"] != "offered"]
    rated = [f for f in eligible if f["risk"] != "unknown"]
    weights = {"critical": 100, "medium": 50, "resilient": 0}
    score = round(sum(weights[f["risk"]] for f in rated) / len(rated), 1) if rated else None
    unique = Counter(f["risk"] for f in eligible)
    review_counts = Counter(f.get("review_reason") or "unspecified" for f in eligible if f["risk"] == "unknown")
    sessions = {(f["evidence"]["source"], f["context"]["session"]) for f in findings
                if f.get("context") and f["context"].get("event") == "server_hello"}
    hybrids = {(f["evidence"]["source"], f["context"]["session"]) for f in findings
               if f.get("context") and f["context"].get("event") == "server_hello" and f["context"].get("hybrid_components")}
    return {
        "schema": "quantumtrace.inventory/1.0", "tool": "QuantumTrace", "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "policy": {
            "name": "junctionx-2026-context-policy-v2",
            "description": "Primitive-level challenge policy; not a certification or a calibrated enterprise risk model.",
            "score_formula": "Mean of critical=100, medium=50, resilient=0 over rated, non-offered findings. Unknowns excluded and reported separately.",
            "limitations": [
                "A zero score is not evidence of a secure system.",
                "Static calls and declared configuration are not proof of runtime execution.",
                "Unknown primitives, parameters and encrypted handshake fields remain unknown.",
                "The number and duplication of observed primitives affect this heuristic score.",
                "Hash tiers extend the brief with an explicit 128-bit ideal quantum-query target; they are not NIST-assigned risk tiers or practical attack estimates.",
            ],
            "hash_target_bits": 128,
        },
        "summary": {
            "total_findings": len(findings), "risk_counts": dict(unique),
            "offered_findings": sum(f["observation"] == "offered" for f in findings),
            "rated_findings": len(rated), "unknown_findings": unique.get("unknown", 0),
            "non_offered_findings": len(eligible), "review_counts": dict(review_counts),
            "classification_coverage_pct": round(100 * len(rated) / len(eligible), 1) if eligible else None,
            "observation_counts": dict(Counter(f["observation"] for f in findings)),
            "input_files": len(files), "tls_sessions": len(sessions), "hybrid_tls_sessions": len(hybrids),
            "quantum_risk_score": score, "analysed_files": sum(f["status"] == "analysed" for f in files),
            "error_files": sum(f["status"] == "error" for f in files),
            "partial_files": sum(f["status"] == "partial" for f in files),
            "unsupported_files": sum(f["status"] == "unsupported" for f in files),
            "elapsed_seconds": round(seconds, 4),
        },
        "files": files, "findings": findings, "warnings": warnings,
        "priorities": build_priorities(findings),
    }
