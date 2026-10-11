"""Offline AWS configuration enrichment from documented, explicit mappings.

No AWS credentials or account access are used. Policy names are resolved only
when present in this versioned mapping; unknown policies stay unresolved.
"""

from .policy import parse_label

AWS_KMS = "https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html"
AWS_ELB = "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html"
CHECKED = "2026-10-10"
FS_GCM = [
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
]
FS_CBC = [
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
]
RSA_MODERN = [
    "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_256_CBC_SHA256",
]
LEGACY_SHA1 = [
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA",
]
TLS13 = ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
POLICIES = {
    "ELBSecurityPolicy-2016-08": (["TLSv1", "TLSv1.1", "TLSv1.2"], FS_GCM + FS_CBC + RSA_MODERN + LEGACY_SHA1),
    "ELBSecurityPolicy-TLS-1-1-2017-01": (["TLSv1.1", "TLSv1.2"], FS_GCM + FS_CBC + RSA_MODERN + LEGACY_SHA1),
    "ELBSecurityPolicy-TLS-1-2-2017-01": (["TLSv1.2"], FS_GCM + FS_CBC + RSA_MODERN),
    "ELBSecurityPolicy-FS-1-2-Res-2020-10": (["TLSv1.2"], FS_GCM),
    "ELBSecurityPolicy-TLS13-1-2-2021-06": (["TLSv1.2", "TLSv1.3"], TLS13 + FS_GCM + FS_CBC),
}


def scan_aws(data, collector):
    """Emit provider-specific findings; return JSON pointers handled here."""
    handled = set()
    if not isinstance(data, dict):
        return handled
    region = data.get("Region")
    keys = data.get("Keys", [])
    if isinstance(keys, list):
        for i, key in enumerate(keys):
            if not isinstance(key, dict) or not ("KeyId" in key or "KeyArn" in key):
                continue
            usage = key.get("KeyUsage")
            role = {"SIGN_VERIFY": "signature", "ENCRYPT_DECRYPT": "encryption-key", "KEY_AGREEMENT": "key-establishment"}.get(usage, "unspecified")
            context = {"provider": "AWS", "asset_id": key.get("KeyArn", key.get("KeyId")), "region": region,
                       "usage": usage, "state": key.get("KeyState"), "mapping_checked": CHECKED}
            for field in ["KeySpec", "SigningAlgorithms", "EncryptionAlgorithms"]:
                if field not in key:
                    continue
                ptr = f"/Keys/{i}/{field}"
                handled.add(ptr)
                values = key[field] if isinstance(key[field], list) else [key[field]]
                for j, value in enumerate(values):
                    loc = f"{ptr}/{j}" if isinstance(key[field], list) else ptr
                    if value == "SYMMETRIC_DEFAULT":
                        if isinstance(region, str) and region.startswith("cn-"):
                            items = [{"algorithm": "SM4", "key_bits": 128, "role": "symmetric-encryption"}]
                        elif isinstance(region, str) and region.startswith(("us-", "eu-", "ap-", "ca-", "sa-", "af-", "me-", "il-", "mx-")):
                            items = [{"algorithm": "AES", "key_bits": 256, "role": "symmetric-encryption"}]
                        else:
                            collector.warn(f"AWS SYMMETRIC_DEFAULT at {loc}: region is missing or unrecognised; the algorithm was not guessed.")
                            items = []
                    else:
                        items = parse_label(value, role)
                    for item in items:
                        item_context = {**context, **({"hash_use": "signature-digest"} if field == "SigningAlgorithms" else {})}
                        if field == "EncryptionAlgorithms" and isinstance(value, str) and "OAEP" in value.upper():
                            item_context["hash_use"] = "oaep-mask-generation"
                        collector.add(**item, observation="configured", locator=loc,
                                      evidence=f"AWS KMS {field}: {value}; resolved using provider documentation",
                                      detector="aws-kms", context=item_context,
                                      caveats=["Declared key configuration and state, not proof of use. Region affects SYMMETRIC_DEFAULT."])
                        if AWS_KMS not in collector.findings[-1]["references"]:
                            collector.findings[-1]["references"].append(AWS_KMS)
                    if not items:
                        collector.warn(f"Unresolved AWS KMS algorithm at {loc}.")
    lbs = data.get("LoadBalancers", [])
    if isinstance(lbs, list):
        for i, lb in enumerate(lbs):
            if not isinstance(lb, dict) or not isinstance(lb.get("Listeners", []), list):
                continue
            for j, listener in enumerate(lb.get("Listeners", [])):
                if not isinstance(listener, dict):
                    continue
                ptr = f"/LoadBalancers/{i}/Listeners/{j}"
                name = listener.get("SslPolicy")
                if name is None:
                    if listener.get("Protocol") == "HTTP":
                        redirects = any(a.get("Type") == "redirect" and a.get("RedirectConfig", {}).get("Protocol") == "HTTPS"
                                        for a in listener.get("DefaultActions", []) if isinstance(a, dict))
                        collector.warn(f"HTTP listener at {ptr}: " + ("configured redirect to HTTPS; no TLS primitives on this listener." if redirects else "no listener-level TLS encryption declared."))
                    continue
                handled.add(ptr + "/SslPolicy")
                if name not in POLICIES:
                    collector.status = "partial"
                    collector.warn(f"Unmapped AWS TLS policy at {ptr}/SslPolicy; no cipher list or resilience was inferred.")
                    continue
                protocols, suites = POLICIES[name]
                context = {"provider": "AWS", "asset_id": listener.get("ListenerArn"), "load_balancer_type": lb.get("Type"),
                           "security_policy": name, "protocols": protocols, "mapping_checked": CHECKED,
                           "certificate_refs": [c.get("CertificateArn") for c in listener.get("Certificates", []) if isinstance(c, dict)]}
                for suite in suites:
                    for item in parse_label(suite):
                        collector.add(**item, observation="configured", locator=ptr + "/SslPolicy",
                                      evidence=f"AWS policy {name} permits {suite}", detector="aws-elb-policy",
                                      context={**context, "cipher_suite": suite, "hash_use": "tls-suite-component"},
                                      caveats=["Policy capability, not evidence of a negotiated connection. TLS 1.3 suites do not identify key exchange or authentication."])
                        if AWS_ELB not in collector.findings[-1]["references"]:
                            collector.findings[-1]["references"].append(AWS_ELB)
                if any(p in {"TLSv1", "TLSv1.1"} for p in protocols):
                    collector.warn(f"AWS TLS policy at {ptr} permits deprecated protocol versions; assess this separately from quantum exposure.")
    return handled
