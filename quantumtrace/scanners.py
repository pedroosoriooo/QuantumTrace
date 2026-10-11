"""Conservative configuration, source and certificate scanners."""

import ast
import re

from .policy import parse_label


ALGORITHM_FIELDS = {
    "algorithm", "algorithms", "keyalgorithm", "keytype", "keyspec",
    "encryption", "encryptionalgorithm", "signingalgorithm", "signaturealgorithm",
    "encryptionalgorithms", "signingalgorithms",
    "signaturescheme", "signatureschemes", "ciphersuite", "ciphersuites",
    "cipher", "ciphers", "supportedgroups", "keyexchange", "keyexchangegroup",
    "keyexchangemechanism", "hashalgorithm", "digest", "kem", "kmskeyspec",
}
SIZE_FIELDS = {"keysize", "keylength", "keybits", "keysizebits", "bits"}


def normalise_key(key):
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def _pointer(parent, key):
    return parent + "/" + str(key).replace("~", "~0").replace("/", "~1")


def scan_config(data, collector):
    from .cloud import scan_aws
    handled = scan_aws(data, collector)
    recognised_fields = 0

    def visit(value, pointer=""):
        nonlocal recognised_fields
        if isinstance(value, list):
            for i, child in enumerate(value):
                visit(child, _pointer(pointer, i))
        elif isinstance(value, dict):
            bits = None
            for k, v in value.items():
                if normalise_key(k) in SIZE_FIELDS and type(v) in {int, str}:
                    try:
                        n = int(v)
                        if 0 < n < 100000:
                            bits = n
                    except ValueError:
                        pass
            for key, child in value.items():
                field = normalise_key(key)
                ptr = _pointer(pointer, key)
                if ptr in handled:
                    recognised_fields += 1
                    continue
                if field in ALGORITHM_FIELDS:
                    recognised_fields += 1
                    labels = child if isinstance(child, list) else [child]
                    role = "key-establishment" if field in {"supportedgroups", "keyexchange", "keyexchangegroup", "keyexchangemechanism", "kem"} else None
                    if "sign" in field:
                        role = "signature"
                    for idx, label in enumerate(labels):
                        items = parse_label(label, role, bits)
                        loc = _pointer(ptr, idx) if isinstance(child, list) else ptr
                        for item in items:
                            context = {"hash_use": "signature-digest"} if role == "signature" else None
                            if field in {"ciphersuite", "ciphersuites", "cipher", "ciphers"} and isinstance(label, str) and label.startswith("TLS_"):
                                context = {"hash_use": "tls-suite-component", "cipher_suite": label}
                            collector.add(**item, observation="configured", locator=loc,
                                          # Expose recognised labels, never the whole value.
                                          evidence=f"{key}: {item['algorithm']}" + (f"; explicit key size {item['key_bits']} bits" if item['key_bits'] else ""),
                                          detector="json-crypto-field", context=context, caveats=["Declared configuration, not proof of runtime use."])
                        if not items:
                            collector.warn(f"Unresolved crypto field at {loc}; no resilience was inferred.")
                if isinstance(child, (dict, list)):
                    visit(child, ptr)

    visit(data)
    if not recognised_fields:
        collector.warn("No recognised crypto fields. This does not imply the configuration is cryptography-free or secure.")


def _name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _name(node.value)
        return f"{prefix}.{node.attr}" if prefix else ""
    return ""


def scan_python(text, collector):
    from .static_facts import PythonFacts
    tree = ast.parse(text)
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    collector.warn("Python analysis is static. Bounded constant and observed-call-site inference is supported; dynamic imports, general data flow and unseen callers remain unresolved.")
    imports = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name.split('.')[0]] = alias.name if alias.asname else alias.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name != "*":
                    imports[alias.asname or alias.name] = node.module + "." + alias.name

    def resolve(name):
        root, dot, tail = name.partition(".")
        return imports.get(root, root) + (dot + tail if dot else "")

    facts = PythonFacts(tree, resolve)

    def hash_name(node):
        if isinstance(node, ast.Call):
            node = node.func
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            label = node.value
        else:
            qualified_hash = resolve(_name(node))
            if not qualified_hash.startswith(("hashlib.", "cryptography.hazmat.primitives.hashes.")):
                return None
            label = qualified_hash.split(".")[-1]
        items = parse_label(label, "hash")
        return next((i["algorithm"] for i in items if i["role"] == "hash"), None)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        qualified = resolve(_name(node.func))
        algorithm, bits, role = None, None, None
        if qualified.startswith(("cryptography.", "Crypto.", "Cryptodome.")):
            if qualified.endswith(("rsa.generate_private_key", "RSA.generate")):
                algorithm = "RSA"
                bits = facts.integer_arg(node, "key_size", 1) if qualified.startswith("cryptography.") else facts.integer_arg(node, "bits", 0)
                role = "public-key"
            elif qualified.endswith(("dsa.generate_private_key", "DSA.generate")):
                algorithm, role = "DSA", "signature"
                bits = facts.integer_arg(node, "key_size", 0) or facts.integer_arg(node, "bits", 0)
            elif qualified.endswith("ec.generate_private_key"):
                algorithm, role = "EC", "unspecified"
            elif qualified.endswith("ec.ECDSA"):
                algorithm, role = "ECDSA", "signature"
            elif qualified.endswith("ec.ECDH"):
                algorithm, role = "ECDH", "key-establishment"
            elif qualified.endswith(("algorithms.AES", "AES.new", "algorithms.AES128", "algorithms.AES256", "aead.AESGCM", "aead.AESCCM")):
                algorithm, role = "AES", "symmetric-encryption"
                if qualified.endswith("AES128"):
                    bits = 128
                elif qualified.endswith("AES256"):
                    bits = 256
                else:
                    key_node = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == "key"), None)
                    length = facts.byte_length(key_node)
                    bits = length * 8 if length is not None else None
            elif qualified.endswith("pbkdf2.PBKDF2HMAC"):
                hash_node = next((kw.value for kw in node.keywords if kw.arg == "algorithm"), None)
                digest = hash_name(hash_node)
                if digest:
                    algorithm, role = "PBKDF2-HMAC-" + digest, "key-derivation"
                    length = facts.integer_arg(node, "length")
                    bits = length * 8 if length is not None else None
            elif qualified.endswith(("algorithms.TripleDES", "DES3.new")):
                algorithm, role = "3DES", "symmetric-encryption"
            else:
                for name in ["Ed25519", "Ed448", "X25519", "X448"]:
                    if re.search(rf"\.{name}PrivateKey\.generate$", qualified):
                        algorithm, role = name, "key-establishment" if name.startswith("X") else "signature"
                for name in ["SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "MD5"]:
                    if qualified.endswith("hashes." + name):
                        algorithm, role = name.replace("SHA", "SHA-"), "hash"
        if qualified.startswith("hashlib."):
            tail = qualified.split(".")[-1].lower()
            if tail in {"md5", "sha1", "sha224", "sha256", "sha384", "sha512"}:
                algorithm, role = tail.upper().replace("SHA", "SHA-"), "hash"
            elif tail == "new" and node.args and isinstance(node.args[0], ast.Constant):
                items = parse_label(node.args[0].value, "hash")
                for item in items:
                    collector.add(**item, observation="static-call", locator=f"line:{node.lineno}", evidence=f"Call to {qualified}", detector="python-ast", confidence="medium")
            elif tail == "pbkdf2_hmac" and node.args:
                digest = hash_name(node.args[0])
                if digest:
                    algorithm, role = "PBKDF2-HMAC-" + digest, "key-derivation"
                    output = facts.integer_arg(node, "dklen", 4)
                    bits = output * 8 if output is not None else None
        if qualified == "hmac.new":
            digest_node = next((kw.value for kw in node.keywords if kw.arg == "digestmod"), None)
            digest_node = digest_node or (node.args[2] if len(node.args) > 2 else None)
            digest = hash_name(digest_node)
            if digest:
                algorithm, role = "HMAC-" + digest, "message-authentication"
        if algorithm:
            context = {"operation": qualified.split(".")[-1]}
            if algorithm.startswith("PBKDF2"):
                context["iterations"] = facts.integer_arg(node, "iterations", 3 if qualified == "hashlib.pbkdf2_hmac" else None)
                salt = next((kw.value for kw in node.keywords if kw.arg == "salt"), None)
                if salt is None and qualified == "hashlib.pbkdf2_hmac" and len(node.args) > 2:
                    salt = node.args[2]
                length = facts.byte_length(salt)
                if length is not None:
                    context["salt_bits"] = length * 8
            if role == "hash":
                parent = parents.get(node)
                if isinstance(parent, ast.keyword):
                    parent = parents.get(parent)
                if isinstance(parent, ast.Call) and resolve(_name(parent.func)).endswith("pbkdf2.PBKDF2HMAC"):
                    context["hash_use"] = "key-derivation-component"
            if algorithm == "AES" and qualified.endswith(("aead.AESGCM", "aead.AESCCM")):
                context["mode"] = "GCM" if qualified.endswith("AESGCM") else "CCM"
            collector.add(algorithm, "static-call", f"line:{node.lineno}", f"Call to {qualified}" + (f"; statically inferred key size {bits} bits" if bits else ""), key_bits=bits,
                          role=role, detector="python-ast", confidence="medium", context=context,
                          caveats=["Static syntactic evidence only. Size inference follows supported constants and observed call sites; unseen callers can use different parameters."])


def _without_comments(text):
    # Preserve strings and newlines; comments are replaced by whitespace.
    pattern = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`[^`]*`|//[^\n]*|/\*[\s\S]*?\*/'
    return re.sub(pattern, lambda m: re.sub(r"[^\n]", " ", m.group()) if m.group().startswith(("//", "/*")) else m.group(), text)


def scan_other_code(text, collector, suffix):
    from .source_patterns import scan_go, scan_java
    clean = _without_comments(text)
    collector.warn("Java/Go analysis uses bounded syntax and observed call sites, not full semantic/type analysis. Dynamic calls, aliases outside known imports and unseen callers may be missed.")
    (scan_java if suffix == ".java" else scan_go)(clean, collector)


def scan_certificate(raw, collector):
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448, x25519, x448
    except ImportError:
        raise ValueError("Install the optional cryptography dependency to inspect certificates.")
    if b"PRIVATE KEY" in raw:
        collector.warn("Private-key material was deliberately not parsed or included in the report.")
        return
    cert = None
    try:
        cert = x509.load_pem_x509_certificate(raw) if b"BEGIN CERTIFICATE" in raw else x509.load_der_x509_certificate(raw)
        key = cert.public_key()
    except ValueError:
        key = serialization.load_pem_public_key(raw) if b"BEGIN PUBLIC KEY" in raw or b"BEGIN RSA PUBLIC KEY" in raw else serialization.load_der_public_key(raw)
    types = [(rsa.RSAPublicKey, "RSA"), (dsa.DSAPublicKey, "DSA"), (ec.EllipticCurvePublicKey, "EC"), (ed25519.Ed25519PublicKey, "Ed25519"), (ed448.Ed448PublicKey, "Ed448"), (x25519.X25519PublicKey, "X25519"), (x448.X448PublicKey, "X448")]
    for typ, name in types:
        if isinstance(key, typ):
            collector.add(name, "key-material", "public-key", f"Parsed {name} public key", key_bits=getattr(key, "key_size", None), role="public-key", detector="cryptography-x509", caveats=["A certificate's subject key and issuer signature are different assets."])
            break
    else:
        collector.warn("Public key type is unsupported; no security conclusion was inferred.")
    if cert is not None:
        oid = cert.signature_algorithm_oid.dotted_string
        # OID identifies the issuer's signature, not the subject public key.
        names = {"1.2.840.113549.1.1.5": "RSA", "1.2.840.113549.1.1.10": "RSA", "1.2.840.113549.1.1.11": "RSA", "1.2.840.113549.1.1.12": "RSA", "1.2.840.113549.1.1.13": "RSA", "1.2.840.10045.4.3.2": "ECDSA", "1.2.840.10045.4.3.3": "ECDSA", "1.2.840.10045.4.3.4": "ECDSA", "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448"}
        if oid in names:
            collector.add(names[oid], "certificate-signature", "issuer-signature", f"Certificate signature algorithm OID {oid}", role="signature", detector="cryptography-x509")
        else:
            collector.warn("Certificate signature algorithm is unsupported; inspect the issuer signature separately.")
