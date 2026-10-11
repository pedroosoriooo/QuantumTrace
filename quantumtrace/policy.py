"""Explicit challenge policy, separate from evidence collection.

These tiers implement the challenge brief. They are not a universal assertion
that AES-128 is currently insecure, or that a PQC algorithm secures a system.
"""

import re

NIST = "https://csrc.nist.gov/projects/post-quantum-cryptography/faqs"
FIPS = {
    "ML-KEM": "https://csrc.nist.gov/pubs/fips/203/final",
    "ML-DSA": "https://csrc.nist.gov/pubs/fips/204/final",
    "SLH-DSA": "https://csrc.nist.gov/pubs/fips/205/final",
}
HASH_REFS = ["https://arxiv.org/abs/quant-ph/9705002", "https://arxiv.org/abs/quant-ph/9605034", NIST]
HASH_BITS = {"SHA-224": 224, "SHA-256": 256, "SHA-384": 384, "SHA-512": 512,
             "SHA3-256": 256, "SHA3-384": 384, "SHA3-512": 512}
TARGET_BITS = 128


def classify(algorithm, key_bits=None, role=None, context=None):
    """Return a classification for an identified primitive, not an entire system."""
    context = context or {}
    result = {
        "risk": "unknown", "quantum_mechanism": "unresolved",
        "explanation": "Insufficient information or an unrecognised primitive.",
        "recommendation": "Review the evidence and identify the primitive and parameters.",
        "standards": [], "references": [NIST], "classical_warning": None,
        "assessment": {"rule_id": "unmapped-primitive", "scope": "primitive", "target_bits": TARGET_BITS,
                       "model": None, "query_exponent_bits": None, "assumptions": []},
        "review_reason": "unrecognised_primitive", "missing_information": ["recognised algorithm and assessment rule"],
    }
    if algorithm in {"RSA", "DSA", "EC", "ECDSA", "ECDH", "DH", "Ed25519", "Ed448", "X25519", "X448"}:
        result.update(
            risk="critical", quantum_mechanism="Shor",
            explanation="Classical public-key primitive relying on factoring or discrete logarithms; vulnerable to a sufficiently capable quantum computer.",
            recommendation="Plan a role-appropriate PQC migration. Use a KEM for key establishment and a signature scheme for signatures; do not substitute one for the other.",
        )
        if algorithm == "RSA" and key_bits is not None and key_bits < 2048:
            result["classical_warning"] = "RSA modulus below 2048 bits also needs classical-security review."
        if algorithm == "DSA":
            result["classical_warning"] = "Legacy DSA should be reviewed independently of quantum migration."
        result["assessment"]["rule_id"] = "classical-public-key-shor"
    elif algorithm in FIPS:
        standard = {"ML-KEM": "NIST FIPS 203", "ML-DSA": "NIST FIPS 204", "SLH-DSA": "NIST FIPS 205"}[algorithm]
        result.update(
            risk="resilient", quantum_mechanism="recognised PQC",
            explanation="Recognised PQC family under the challenge policy. This does not certify the implementation, parameters, or surrounding protocol.",
            recommendation="Verify the standardised variant, implementation, parameters and deployment. A PQC component alone does not make the whole system quantum-resilient.",
            standards=[standard], references=[FIPS[algorithm]],
        )
        result["assessment"]["rule_id"] = "final-pqc-family"
    elif algorithm in {"Kyber", "Dilithium", "SPHINCS+"}:
        result.update(
            explanation="Pre-standard family name. An exact variant/version is needed before claiming conformance to ML-KEM, ML-DSA or SLH-DSA.",
            recommendation="Identify the version and verify correspondence with the final NIST standard; a family-name match is not conformance evidence.",
            quantum_mechanism="PQC candidate / legacy name",
            review_reason="legacy_variant", missing_information=["exact variant and version corresponding to the final standard"],
        )
        result["assessment"]["rule_id"] = "legacy-pqc-name-review"
    elif algorithm == "AES":
        if key_bits in {128, 192}:
            result.update(
                risk="medium", quantum_mechanism="Grover (challenge policy)",
                explanation="Challenge-policy tier for symmetric keys below 256 bits. Grover's practical impact is nuanced; this is not a claim that AES is currently broken.",
                recommendation="Review confidentiality lifetime and policy; consider AES-256 where appropriate. Separately check modes, nonce handling and key management.",
            )
        elif key_bits == 256:
            result.update(
                risk="resilient", quantum_mechanism="large-key symmetric",
                explanation="AES-256 is in the challenge's resilient primitive tier. Modes, key handling, and public-key mechanisms remain separate risks.",
                recommendation="Retain appropriate symmetric protection and separately inventory key exchange and signatures.",
            )
        else:
            result.update(explanation="AES identified but key size is unknown or invalid; no resilient classification is inferred.", recommendation="Determine the actual AES key length (128, 192 or 256 bits).")
            result.update(review_reason="missing_parameters", missing_information=["valid AES key length (128, 192 or 256 bits)"])
        result["assessment"]["rule_id"] = "aes-key-size"
    elif algorithm in {"3DES", "DES", "RC4", "MD5", "SHA-1"}:
        result.update(
            risk="medium", quantum_mechanism="Grover / quantum search (challenge policy)",
            explanation="Challenge-policy medium tier; classical weaknesses must also be addressed.",
            recommendation="Remove deprecated cryptography using role-appropriate replacements, independently of quantum migration.",
            classical_warning="Deprecated or classically weak primitive; assess the specific usage, not only quantum exposure.",
        )
        result["assessment"]["rule_id"] = "deprecated-primitive-challenge-tier"
    elif algorithm in HASH_BITS:
        n = HASH_BITS[algorithm]
        usage = context.get("hash_use")
        # Signature digests and transcript hashes need collision resistance.
        # TLS suite hashes have several roles: use the weaker generic model
        # as an explicitly conservative component-level policy, not a claim
        # that every PRF/MAC has collision-attack complexity.
        if usage in {"signature-digest", "tls-suite-component", "collision-resistance"}:
            model, exponent = "generic quantum collision queries (n/3)", n / 3
        elif usage in {"preimage-resistance", "key-derivation-component"}:
            model, exponent = "generic quantum preimage queries (n/2)", n / 2
        elif n >= 384:
            model, exponent = "conservative generic collision queries (n/3)", n / 3
        else:
            model, exponent = None, None
        result["assessment"].update(rule_id="hash-generic-query-policy", model=model,
                                    query_exponent_bits=round(exponent, 1) if exponent is not None else None,
                                    hash_use=usage or "not-established", digest_bits=n,
                                    assumptions=["Ideal black-box query model; query exponent is not wall-clock attack cost or a NIST security category.",
                                                 "Primitive-level 128-bit query target chosen for this project; no protocol or implementation certification."])
        if usage == "tls-suite-component":
            result["assessment"]["assumptions"].append("Conservative collision model for the TLS hash component; HKDF and MAC uses are not independently assessed.")
        if not usage and n >= 384:
            result["assessment"]["assumptions"].append("Purpose is unspecified; the weaker collision model is used rather than assuming a preimage-only use.")
        result.update(references=HASH_REFS, quantum_mechanism="generic quantum hash queries")
        if exponent is None:
            result.update(explanation="Hash identified, but its security purpose is missing; collision and preimage policies give different tiers.",
                          recommendation="Identify whether this hash protects a signature/transcript, preimage, KDF or another construction.",
                          review_reason="missing_context", missing_information=["hash security purpose (collision versus preimage resistance)"])
            if usage:
                result.update(explanation="Hash and construction identified, but this construction needs a dedicated assessment rule. A standalone collision or preimage tier is not inferred.",
                              recommendation="Review the hash within its identified construction. Assess any associated classical public-key component separately.",
                              review_reason="policy_gap", missing_information=[f"construction-aware hash assessment rule for {usage}"])
        else:
            result.update(risk="resilient" if exponent >= TARGET_BITS else "medium",
                          explanation=f"Project policy: {n}-bit digest assessed using {model}; generic query exponent {exponent:.1f} bits against a {TARGET_BITS}-bit target. This is a model-based primitive tier, not evidence of a practical break.",
                          recommendation="Check the documented model and usage. Assess signatures, key exchange and secret entropy separately; use a larger digest where the chosen collision-resistance target requires it.")
    elif algorithm == "ChaCha20":
        result["assessment"]["rule_id"] = "chacha20-key-size"
        result["references"] = ["https://www.rfc-editor.org/rfc/rfc8439.html", NIST]
        if key_bits in {128, 256}:
            result.update(risk="resilient" if key_bits == 256 else "medium", quantum_mechanism="large-key symmetric / generic key search",
                          explanation=f"ChaCha20 with an identified {key_bits}-bit key: the project applies the same large-key symmetric tier as AES. Authentication tags, nonces, entropy and surrounding key exchange are assessed separately.",
                          recommendation="Verify the exact variant and key generation; ensure nonce uniqueness and assess the authentication construction separately.")
            result["assessment"].update(model="generic quantum key search (k/2)", query_exponent_bits=key_bits / 2,
                                        assumptions=["Uniform secret key and supported 20-round variant; primitive-level classification only."])
        else:
            result.update(explanation="ChaCha20 identified but the variant/key length is not established.",
                          recommendation="Identify the variant and key size; a known IETF TLS suite establishes a 256-bit encryption key.",
                          review_reason="missing_parameters", missing_information=["ChaCha20 variant and key length"])
    elif algorithm.startswith("PBKDF2-HMAC-"):
        missing = ["password entropy / password-selection policy"]
        if not key_bits:
            missing.append("derived-key output length")
        if not context.get("iterations"):
            missing.append("iteration count")
        if not context.get("salt_bits"):
            missing.append("salt length")
        missing.append("salt generation and uniqueness")
        result.update(quantum_mechanism="password-search / usage-dependent KDF",
                      explanation="PBKDF2 identified. Output length and iterations do not establish password entropy; a 256-bit output must not be labelled a 256-bit secret.",
                      recommendation="Review password entropy, salt generation, iterations and the deployment threat model. Keep the derived length separate from secret security strength.",
                      review_reason="missing_parameters", missing_information=missing,
                      references=["https://www.rfc-editor.org/rfc/rfc8018.html", NIST])
        result["assessment"]["rule_id"] = "password-kdf-entropy-review"
    elif algorithm.startswith(("HMAC-SHA-", "HMAC-SHA3-")):
        result.update(quantum_mechanism="secret-key / usage-dependent authentication",
                      explanation="HMAC identified. The digest name alone does not establish key entropy, tag truncation or the authentication threat model.",
                      recommendation="Identify key generation/entropy, actual tag length and whether the construction is a MAC or a password-KDF component.",
                      review_reason="missing_parameters", missing_information=["secret-key entropy and generation", "actual authentication-tag length / construction role"],
                      references=["https://www.rfc-editor.org/rfc/rfc2104", NIST])
        result["assessment"]["rule_id"] = "hmac-parameter-review"
    elif algorithm.startswith(("SHA", "HMAC", "PBKDF")):
        result.update(
            quantum_mechanism="usage-dependent quantum security",
            explanation="Primitive identified; this prototype does not assign a universal resilience tier without a usage-specific policy (e.g. preimage versus collision resistance).",
            recommendation="Review the operation, required security strength and deployment policy. This is an explicit policy-coverage gap.",
            review_reason="policy_gap", missing_information=["assessment rule for this recognised family"],
        )
    if result["risk"] != "unknown":
        result.update(review_reason=None, missing_information=[])
    if context.get("hybrid_components") and result["risk"] == "critical":
        result["explanation"] += " This is a component of a hybrid group; its tier does not prove the combined hybrid is quantum-vulnerable."
        result["recommendation"] = "Review the complete hybrid construction, combiner, standardised variant and implementation together with its PQC component. Do not replace the hybrid solely because its classical component is critical. Assess authentication separately."
    return result


def parse_label(label, role=None, key_bits=None):
    """Parse crypto labels in known algorithm fields. Never scan arbitrary prose."""
    if not isinstance(label, str):
        return []
    text = label.upper()
    # Algorithm labels from Java and AWS encode components without separators.
    text = re.sub(r"WITH", "_", text)
    text = re.sub(r"RSASSA(?:[_-](?:PKCS1[_-]V1[_-]5|PSS))?", "RSA", text)
    text = re.sub(r"RSAES[_-]OAEP", "RSA", text)
    text = re.sub(r"ECC_NIST_P(256|384|521)", r"EC_P_\1", text)
    text = re.sub(r"SHA[_-](224|256|384|512)", r"SHA\1", text)
    text = re.sub(r"(X25519|SECP256R1|SECP384R1)(MLKEM(?:512|768|1024))", r"\1_\2", text)
    found = []

    def add(name, bits=None, actual_role=None):
        item = {"algorithm": name, "key_bits": bits, "role": actual_role or role or "unspecified"}
        if item not in found:
            found.append(item)

    composed = re.search(r"PBKDF2_?HMAC_?SHA(256|384|512)", text)
    hmac = re.search(r"HMAC_?SHA(256|384|512)", text)
    if composed:
        add("PBKDF2-HMAC-SHA-" + composed.group(1), key_bits, "key-derivation")
        text = text.replace(composed.group(), " ")
    elif hmac:
        add("HMAC-SHA-" + hmac.group(1), key_bits, "message-authentication")
        text = text.replace(hmac.group(), " ")

    # TLS suites contain multiple primitives. Boundary-aware patterns avoid
    # detecting DSA inside ECDSA or DH inside unrelated identifiers.
    boundary = r"(?<![A-Z0-9]){}(?![A-Z0-9])"
    for name, pat in [
        ("ML-KEM", r"ML[-_]?KEM(?:[-_]?\d+)?"),
        ("ML-DSA", r"ML[-_]?DSA(?:[-_]?\d+)?"),
        ("SLH-DSA", r"SLH[-_]?DSA(?:[-_][A-Z0-9]+)*"),
        ("Kyber", r"KYBER(?:\d+)?"),
        ("Dilithium", r"DILITHIUM(?:\d+)?"),
        ("SPHINCS+", r"SPHINCS\+"),
    ]:
        if re.search(boundary.format(pat), text):
            # ML-KEM-768 is a parameter-set name, not a 768-bit secret key.
            add(name, None, "key-establishment" if name in {"ML-KEM", "Kyber"} else "signature")
            # Do not classify the DSA token within ML-DSA or SLH-DSA as
            # classical DSA. Preserve other components of hybrid names.
            text = re.sub(boundary.format(pat), " ", text)
    for name in ["ECDSA", "Ed25519", "Ed448", "RSA", "DSA", "X25519", "X448"]:
        if re.search(boundary.format(name.upper()), text):
            inferred = re.search(r"RSA[_-]?(\d{3,5})(?!\d)", text) if name == "RSA" else None
            bits = int(inferred.group(1)) if inferred else key_bits
            add(name, bits, "signature" if name in {"ECDSA", "Ed25519", "Ed448", "DSA"} else role)
        elif name == "RSA":
            match = re.search(boundary.format(r"RSA[_-]?\d{3,5}"), text)
            if match:
                add("RSA", int(re.search(r"\d+", match.group()).group()), role)
    if re.search(boundary.format(r"ECDH(?:E)?"), text):
        add("ECDH", key_bits, "key-establishment")
    if re.search(boundary.format(r"DH(?:E)?"), text):
        add("DH", key_bits, "key-establishment")
    curve = re.search(boundary.format(r"SECP(\d+)[RK]1|PRIME(256)V1|P[-_](256|384|521)"), text)
    if curve:
        curve_bits = int(next(g for g in curve.groups() if g))
        add("ECDH" if role == "key-establishment" else "EC", curve_bits, role)
    aes = re.search(boundary.format(r"AES(?:[_-]?(128|192|256))?"), text)
    if aes:
        add("AES", int(aes.group(1)) if aes.group(1) else key_bits, "symmetric-encryption")
    if re.search(boundary.format(r"(?:3DES|DES[-_]EDE3|TRIPLEDES|DESEDE)"), text):
        add("3DES", None, "symmetric-encryption")
    elif re.search(boundary.format("DES"), text):
        add("DES", None, "symmetric-encryption")
    for name, pat in [("SHA-1", r"SHA[-_]?1|SHA"), ("SHA-224", r"SHA[-_]?224"), ("SHA-256", r"SHA[-_]?256"), ("SHA-384", r"SHA[-_]?384"), ("SHA-512", r"SHA[-_]?512"), ("MD5", "MD5"), ("RC4", "RC4"), ("ChaCha20", "CHACHA20")]:
        if re.search(boundary.format(pat), text):
            bits = (256 if text == "TLS_CHACHA20_POLY1305_SHA256" else key_bits) if name == "ChaCha20" else None
            add(name, bits, "hash" if name.startswith("SHA") or name == "MD5" else "symmetric-encryption")
    return found
