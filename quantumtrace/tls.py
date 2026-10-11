"""TLS evidence ingestion: normalised JSON or passive TShark capture parsing.

No network probe, capture execution, packet injection or decryption is performed.
The parser deliberately distinguishes ClientHello offers from ServerHello choices.
"""

import json
import shutil
import subprocess

from .policy import parse_label

CIPHERS = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384", 0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
}
GROUPS = {23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 29: "X25519", 30: "X448", 256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096", 259: "ffdhe6144", 260: "ffdhe8192"}
# IANA TLS Supported Groups, checked against the registry on 2026-10-10.
GROUPS.update({512: "MLKEM512", 513: "MLKEM768", 514: "MLKEM1024", 4587: "SecP256r1MLKEM768", 4588: "X25519MLKEM768", 4589: "SecP384r1MLKEM1024"})
SIGNATURES = {0x0401: "RSA_SHA256", 0x0501: "RSA_SHA384", 0x0601: "RSA_SHA512", 0x0403: "ECDSA_SHA256", 0x0503: "ECDSA_SHA384", 0x0603: "ECDSA_SHA512", 0x0804: "RSA_PSS_SHA256", 0x0805: "RSA_PSS_SHA384", 0x0806: "RSA_PSS_SHA512", 0x0807: "Ed25519", 0x0808: "Ed448", 0x0809: "RSA_PSS_SHA256"}


def _number(value):
    try:
        if isinstance(value, str):
            return int(value, 16) if value.lower().startswith("0x") else int(value)
        if type(value) is int:
            return value
    except (ValueError, TypeError):
        pass
    return None


def _as_list(value):
    return value if isinstance(value, list) else ([] if value is None else [value])


def _label(value, mapping):
    numeric = _number(value)
    return mapping.get(numeric) if numeric is not None else value if isinstance(value, str) else None


def _emit(value, mapping, role, observation, locator, collector, context):
    label = _label(value, mapping)
    if label is None:
        collector.warn(f"Unmapped TLS identifier at {locator}; no algorithm was guessed.")
        return
    if label.startswith("ffdhe"):
        items = [{"algorithm": "DH", "key_bits": int(label[5:]), "role": "key-establishment"}]
    else:
        items = parse_label(label, role)
    if not items:
        collector.warn(f"Unresolved TLS mechanism at {locator}; this inventory may be incomplete.")
    hybrid = len([i for i in items if i["role"] == "key-establishment"]) > 1
    for item in items:
        hash_use = "signature-digest" if role == "signature" else "tls-suite-component" if label.startswith("TLS_") else None
        collector.add(**item, observation=observation, locator=locator,
                      evidence=f"TLS {observation}: {label}", detector="tls-handshake",
                      context={**context, "mechanism": label, "hybrid_components": hybrid, **({"hash_use": hash_use} if hash_use else {})},
                      caveats=["Component-level classification: a classical component of a hybrid KEM does not by itself prove the hybrid is quantum-vulnerable."] if hybrid else [])


def _events(events, collector):
    for i, event in enumerate(events):
        if not isinstance(event, dict):
            collector.warn(f"Malformed TLS event at index {i}.")
            continue
        kind = event.get("type")
        if kind not in {"client_hello", "server_hello", "certificate_verify", "server_key_exchange"}:
            collector.warn(f"Unsupported TLS event type at index {i}.")
            continue
        context = {k: event[k] for k in ["frame", "source_ip", "destination_ip", "source_port", "destination_port", "offered_versions"] if k in event}
        context.update(session=str(event.get("session", "unknown")), event=kind, protocol=str(event.get("protocol", "unknown")))
        loc = str(event.get("locator", f"/events/{i}"))
        if kind == "client_hello":
            for field, mapping, role in [("cipher_suites", CIPHERS, None), ("supported_groups", GROUPS, "key-establishment"), ("signature_schemes", SIGNATURES, "signature")]:
                for j, value in enumerate(_as_list(event.get(field))):
                    _emit(value, mapping, role, "offered", f"{loc}/{field}/{j}", collector, context)
        elif kind == "server_hello":
            if "cipher_suite" in event:
                _emit(event["cipher_suite"], CIPHERS, None, "negotiated", loc + "/cipher_suite", collector, context)
            if "key_share_group" in event:
                _emit(event["key_share_group"], GROUPS, "key-establishment", "negotiated", loc + "/key_share_group", collector, context)
            else:
                collector.warn(f"Session {context['session']}: key exchange group was not identified. TLS 1.3 cipher suites do not identify key exchange or authentication.")
            collector.warn(f"Session {context['session']}: ServerHello does not establish complete authentication or system resilience; encrypted handshake fields may be unavailable.")
        elif kind == "certificate_verify" and "signature_scheme" in event:
            _emit(event["signature_scheme"], SIGNATURES, "signature", "negotiated", loc + "/signature_scheme", collector, context)
        elif kind == "server_key_exchange" and "group" in event:
            _emit(event["group"], GROUPS, "key-establishment", "negotiated", loc + "/group", collector, context)


def _flatten(value, result=None):
    result = {} if result is None else result
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(child, list) and all(not isinstance(v, (dict, list)) for v in child):
                result.setdefault(key, []).extend(child)
            elif isinstance(child, (dict, list)):
                _flatten(child, result)
            else:
                result.setdefault(key, []).append(child)
    elif isinstance(value, list):
        for child in value:
            _flatten(child, result)
    return result


def _tshark_events(packets, collector):
    events = []
    for packet in packets:
        if not isinstance(packet, dict):
            continue
        flat = _flatten(packet.get("_source", {}).get("layers", {}))
        raw_types = flat.get("tls.handshake.type", [])
        types = {_number(v) for v in raw_types}
        if len(types) != 1 or len(raw_types) != 1:
            if types:
                collector.warn("A packet contains multiple handshake types; combined fields were skipped to avoid mixing offered and negotiated mechanisms.")
            continue
        typ = next(iter(types))
        selected_version = flat.get("tls.handshake.extensions.supported_version", [])
        legacy_version = flat.get("tls.handshake.version", [])
        versions = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
        protocol = versions.get(_number((selected_version or legacy_version or [None])[0]), "unknown") if typ == 2 else "TLS (offer)" if typ == 1 else "unknown"
        event = {"session": str(flat.get("tcp.stream", ["unknown"])[0]), "protocol": protocol}
        frame = flat.get("frame.number", [])
        if len(frame) == 1:
            event["frame"] = frame[0]
            event["locator"] = f"frame:{frame[0]}"
        for field, key in [("ip.src", "source_ip"), ("ip.dst", "destination_ip"), ("tcp.srcport", "source_port"), ("tcp.dstport", "destination_port")]:
            if len(flat.get(field, [])) == 1:
                event[key] = flat[field][0]
        if typ == 1:
            event["offered_versions"] = [versions.get(_number(v), "unknown") for v in selected_version]
            event.update(type="client_hello", cipher_suites=flat.get("tls.handshake.ciphersuite", []), supported_groups=flat.get("tls.handshake.extensions_supported_group", []), signature_schemes=flat.get("tls.handshake.sig_hash_alg", []))
        elif typ == 2:
            random = flat.get("tls.handshake.random", [])
            if any(str(v).replace(":", "").lower() == "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c" for v in random):
                collector.warn("HelloRetryRequest observed: requested cipher/group was not treated as a completed negotiation.")
                continue
            event["type"] = "server_hello"
            cipher = flat.get("tls.handshake.ciphersuite", [])
            if len(cipher) == 1:
                event["cipher_suite"] = cipher[0]
            elif cipher:
                collector.warn("Ambiguous ServerHello cipher suite; not treated as negotiated.")
            group = flat.get("tls.handshake.extensions_key_share_group", [])
            if len(group) == 1:
                event["key_share_group"] = group[0]
        elif typ == 15:
            signatures = flat.get("tls.handshake.sig_hash_alg", [])
            if len(signatures) != 1:
                continue
            event.update(type="certificate_verify", signature_scheme=signatures[0])
        else:
            continue
        events.append(event)
    return events


def scan_tls_json(data, collector):
    if isinstance(data, dict) and data.get("format") == "quantumtrace.tls/1.0":
        if not isinstance(data.get("events"), list):
            raise ValueError("TLS export must contain an events array.")
        _events(data["events"], collector)
        return True
    if isinstance(data, list) and data and all(isinstance(p, dict) and "_source" in p for p in data):
        events = _tshark_events(data, collector)
        _events(events, collector)
        if not events:
            collector.warn("No supported TLS handshake events were extracted from this TShark export.")
        return True
    return False


def scan_capture(path, collector):
    collector.warn("Capture inspection covers supported TLS handshake fields only. SSH, application payloads and other protocols are outside this detector's scope.")
    from .runtime import find_tshark
    executable = find_tshark()
    if not executable:
        collector.status = "partial"
        collector.warn("TShark is not installed: this packet capture was not inspected. Install Wireshark/TShark or supply a TShark JSON export.")
        return
    try:
        result = subprocess.run([executable, "-n", "-r", str(path), "-Y", "tls.handshake", "-T", "json", "--no-duplicate-keys"], capture_output=True, timeout=45, check=False)
    except (OSError, subprocess.TimeoutExpired):
        collector.status = "partial"
        collector.warn("TShark could not complete passive capture parsing within the time limit.")
        return
    if result.returncode != 0 or len(result.stdout) > 50 * 1024 * 1024:
        collector.status = "partial"
        collector.warn("TShark parsing failed or output exceeded the limit; no result was inferred.")
        return
    packets = json.loads(result.stdout)
    events = _tshark_events(packets, collector)
    _events(events, collector)
    if not events:
        collector.warn("No supported TLS handshakes found; this does not prove absence of cryptography.")
