"""Bounded Java/Go syntax analysis with scope-aware constant inference.

This is deliberately smaller than a compiler. Strings and comments are masked
before locating calls. Unknown or conflicting values are never executed or
guessed. Parameter sizes may follow observed call sites, not unseen callers.
"""

import ast
import re

from .policy import parse_label

STRING = r'"(?:\\.|[^"\\])*"|`[^`]*`|\'(?:\\.|[^\'\\])*\''


def mask_strings(text):
    return re.sub(STRING, lambda m: re.sub(r"[^\n]", " ", m.group()), text)


def closing(mask, start, opening="(", end=")"):
    depth = 0
    for i in range(start, len(mask)):
        if mask[i] == opening:
            depth += 1
        elif mask[i] == end:
            depth -= 1
            if depth == 0:
                return i
    return None


def split_args(text):
    mask = mask_strings(text)
    result, start, depth = [], 0, 0
    for i, ch in enumerate(mask):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            result.append(text[start:i].strip())
            start = i + 1
    if text.strip():
        result.append(text[start:].strip())
    return result


def calls(text, pattern):
    masked = mask_strings(text)
    for match in re.finditer(pattern + r"\s*\(", masked):
        opening = match.end() - 1
        end = closing(masked, opening)
        if end is not None:
            yield match, split_args(text[opening + 1:end])


class PatternFacts:
    def __init__(self, text, language):
        self.text, self.masked, self.language = text, mask_strings(text), language
        self.functions = []
        pattern = (r"\bfunc\s+(\w+)\s*\(([^)]*)\)[^{\n]*\{" if language == "go" else
                   r"\b(?:public|private|protected)\s+(?:static\s+)?[\w<>\[\]]+\s+(\w+)\s*\(([^)]*)\)(?:\s+throws\s+[\w., ]+)?\s*\{")
        for m in re.finditer(pattern, self.masked):
            end = closing(self.masked, m.end() - 1, "{", "}")
            if end is None:
                continue
            raw_params = self.text[m.start(2):m.end(2)]
            params = []
            for p in split_args(raw_params):
                tokens = p.strip().split()
                if tokens:
                    params.append(tokens[0] if language == "go" else tokens[-1])
            self.functions.append({"name": m.group(1), "params": params, "start": m.end(), "end": end})

    def scope(self, pos):
        return next((f for f in self.functions if f["start"] <= pos < f["end"]), None)

    def scope_text(self, scope):
        if scope:
            return self.text[scope["start"]:scope["end"]], scope["start"]
        chars = list(self.text)
        for f in self.functions:
            chars[f["start"]:f["end"]] = " " * (f["end"] - f["start"])
        return "".join(chars), 0

    def binding(self, name, scope):
        text, offset = self.scope_text(scope)
        matches = list(re.finditer(r"\b" + re.escape(name) + r"\s*(?::=|=(?!=))", mask_strings(text)))
        if len(matches) != 1:
            return None, None
        m = matches[0]
        stop = re.search(r"[;\n]", mask_strings(text)[m.end():])
        end = m.end() + stop.start() if stop else len(text)
        return text[m.end():end].strip(), offset + m.start()

    def value(self, expression, pos, depth=0):
        if not expression or depth > 12:
            return None
        expression = expression.strip()
        scope = self.scope(pos)
        recurse = lambda e, p=pos: self.value(e, p, depth + 1)
        if re.fullmatch(r"\d[\d_]*", expression):
            n = int(expression.replace("_", ""))
            return n if n < 1_000_000 else None
        if re.fullmatch(r'"(?:\\.|[^"\\])*"', expression):
            try:
                return ast.literal_eval(expression)
            except (ValueError, SyntaxError):
                return None
        if re.fullmatch(r"[A-Za-z_]\w*", expression):
            value, where = self.binding(expression, scope)
            if where is not None:
                if where >= pos:
                    return None
                return recurse(value, where)
            # A local binding that was assigned more than once must not fall
            # through to a global value of the same name.
            local, _ = self.scope_text(scope)
            if scope and re.search(r"\b" + re.escape(expression) + r"\s*(?::=|=(?!=))", mask_strings(local)):
                return None
            if scope and expression in scope["params"]:
                index = scope["params"].index(expression)
                values = []
                for call, arguments in calls(self.text, r"\b" + re.escape(scope["name"])):
                    # Declaration syntax has no brace scope yet and is ignored.
                    if not self.scope(call.start()):
                        continue
                    values.append(recurse(arguments[index], call.start()) if len(arguments) > index else None)
                return values[0] if values and values[0] is not None and all(v == values[0] for v in values) else None
            if scope:
                value, where = self.binding(expression, None)
                if where is not None:
                    return recurse(value, where)
        if self.language == "go":
            byte = re.fullmatch(r"\[\]byte\s*\((.*)\)", expression, re.S)
            if byte:
                value = recurse(byte.group(1))
                return ("bytes", len(value.encode("utf-8"))) if isinstance(value, str) else None
            make = re.fullmatch(r"make\s*\(\s*\[\]byte\s*,\s*(.*?)\s*\)", expression, re.S)
            if make:
                length = recurse(make.group(1))
                return ("bytes", length) if type(length) is int else None
        else:
            byte_array = re.fullmatch(r"new\s+byte\s*\[\s*(.*?)\s*\]", expression, re.S)
            if byte_array:
                length = recurse(byte_array.group(1))
                return ("bytes", length) if type(length) is int and length >= 0 else None
            getbytes = re.fullmatch(r"(.*?)\.getBytes\s*\(\s*StandardCharsets\.UTF_8\s*\)", expression, re.S)
            if getbytes:
                value = recurse(getbytes.group(1))
                return ("bytes", len(value.encode("utf-8"))) if isinstance(value, str) else None
            generator = re.fullmatch(r"KeyGenerator\.getInstance\s*\((.*)\)", expression, re.S)
            if generator:
                label = recurse(generator.group(1))
                if label == "AES" and scope:
                    local, offset = self.scope_text(scope)
                    variable = re.search(r"(\w+)\s*=\s*KeyGenerator\.getInstance", self.text[max(scope["start"], pos - 80):pos + len(expression) + 80])
                    if variable:
                        sizes = [recurse(a[0], offset + m.start()) for m, a in calls(local, r"\b" + variable.group(1) + r"\.init") if a]
                        if len(sizes) == 1 and type(sizes[0]) is int:
                            return ("bytes", sizes[0] // 8)
            gen_result = re.fullmatch(r"(\w+)\.generateKey\s*\(\s*\)", expression)
            if gen_result:
                return recurse(gen_result.group(1))
            key_spec = re.fullmatch(r"new\s+SecretKeySpec\s*\((.*)\)", expression, re.S)
            if key_spec:
                args = split_args(key_spec.group(1))
                return recurse(args[0]) if args else None
        fn = re.fullmatch(r"(\w+)\s*\(\s*\)", expression)
        if fn:
            function = next((f for f in self.functions if f["name"] == fn.group(1) and not f["params"]), None)
            if function:
                local, offset = self.scope_text(function)
                returns = list(re.finditer(r"\breturn\s+([^;\n}]+)", mask_strings(local)))
                if len(returns) == 1:
                    m = returns[0]
                    return recurse(local[m.start(1):m.end(1)], offset + m.start())
        return None

    def key_bits(self, expression, pos):
        value = self.value(expression, pos)
        return value[1] * 8 if isinstance(value, tuple) and value[0] == "bytes" else None


def scan_java(text, collector):
    facts = PatternFacts(text, "java")
    patterns = {
        "Cipher": "symmetric-encryption", "KeyPairGenerator": "public-key",
        "KeyGenerator": "symmetric-encryption", "Signature": "signature",
        "MessageDigest": "hash", "Mac": "message-authentication",
        "SecretKeyFactory": "key-derivation",
    }
    for api, role in patterns.items():
        for m, args in calls(text, r"\b" + api + r"\s*\.\s*getInstance"):
            label = facts.value(args[0], m.start()) if args else None
            if not isinstance(label, str):
                collector.warn(f"Unresolved Java crypto API argument at line {text.count(chr(10), 0, m.start()) + 1}.")
                continue
            bits, mode = None, None
            scope = facts.scope(m.start())
            local, offset = facts.scope_text(scope)
            before = text[max(offset, m.start() - 90):m.start()]
            variable = re.search(r"\b(\w+)\s*=\s*$", before)
            if variable and api in {"KeyGenerator", "KeyPairGenerator"}:
                initializers = [facts.value(a[0], offset + match.start()) for match, a in calls(local, r"\b" + variable.group(1) + r"\s*\.\s*(?:init|initialize)") if a]
                if len(initializers) == 1 and type(initializers[0]) is int:
                    bits = initializers[0]
            if variable and api == "Cipher":
                sizes = [facts.key_bits(a[1], offset + match.start()) for match, a in calls(local, r"\b" + variable.group(1) + r"\s*\.\s*init") if len(a) > 1]
                if sizes and sizes[0] is not None and all(n == sizes[0] for n in sizes):
                    bits = sizes[0]
            if "/" in label:
                mode = label.split("/")[1]
            kdf_context = {}
            if variable and api == "SecretKeyFactory" and "PBKDF2" in label.upper():
                # Follow only the spec passed to this factory. Do not borrow
                # parameters from an unrelated PBEKeySpec in the same method.
                uses = [(match, a) for match, a in calls(local, r"\b" + variable.group(1) + r"\s*\.\s*generateSecret") if a]
                if len(uses) == 1:
                    match, args = uses[0]
                    expression, where = facts.binding(args[0], scope)
                    spec = list(calls(expression or "", r"\bPBEKeySpec"))
                    if where is not None and where < offset + match.start() and len(spec) == 1 and len(spec[0][1]) == 4:
                        parameters = spec[0][1]
                        length = facts.value(parameters[3], where)
                        bits = length if type(length) is int and length > 0 else None
                        iterations = facts.value(parameters[2], where)
                        kdf_context["iterations"] = iterations if type(iterations) is int else None
                        salt_bits = facts.key_bits(parameters[1], where)
                        if salt_bits is not None:
                            kdf_context["salt_bits"] = salt_bits
            for item in parse_label(label, role, bits):
                context = {"operation": api + ".getInstance", "mode": mode, **kdf_context}
                if api == "Signature":
                    context["hash_use"] = "signature-digest"
                collector.add(**item, observation="static-call", locator=f"line:{text.count(chr(10), 0, m.start()) + 1}",
                              evidence=f"Java {api}.getInstance: {label}" + (f"; statically inferred key size {bits} bits" if bits else ""),
                              detector="java-pattern", confidence="medium", context=context,
                              caveats=["Bounded syntax and observed-call-site inference; types, unseen callers and runtime execution are not proven."])
                if mode == "ECB" and item["algorithm"] == "AES":
                    collector.findings[-1]["classical_warning"] = "ECB mode leaks repeated-block structure; address mode/key management separately from quantum tier."


def scan_go(text, collector):
    facts = PatternFacts(text, "go")
    namespaces = {}
    for m in re.finditer(r'(\w+\s+)?"crypto/(rsa|ecdsa|ed25519|aes|hmac|sha1|sha256|sha512|md5)"', text):
        namespaces[m.group(1).strip() if m.group(1) else m.group(2)] = m.group(2)
    # Keep support for standalone snippets, but honour explicit aliases.
    if not namespaces:
        namespaces = {n: n for n in ["rsa", "ecdsa", "ed25519", "aes", "hmac", "sha1", "sha256", "sha512", "md5"]}
    for alias, package in namespaces.items():
        for m, args in calls(text, r"\b" + re.escape(alias) + r"\s*\.\s*(\w+)"):
            operation = m.group(1)
            algorithm, role, bits = None, None, None
            if package == "rsa" and operation in {"GenerateKey", "SignPKCS1v15", "VerifyPKCS1v15", "SignPSS", "VerifyPSS", "EncryptOAEP", "DecryptOAEP"}:
                algorithm, role = "RSA", "public-key" if operation == "GenerateKey" else "signature" if "Sign" in operation or "Verify" in operation else "encryption-key"
                if operation == "GenerateKey" and len(args) > 1:
                    value = facts.value(args[1], m.start())
                    bits = value if type(value) is int else None
            elif package in {"ecdsa", "ed25519"} and operation in {"GenerateKey", "Sign", "Verify", "SignASN1", "VerifyASN1"}:
                algorithm, role = ("ECDSA" if package == "ecdsa" else "Ed25519"), "signature"
            elif package == "aes" and operation == "NewCipher":
                algorithm, role = "AES", "symmetric-encryption"
                bits = facts.key_bits(args[0], m.start()) if args else None
            elif package in {"sha1", "sha256", "sha512", "md5"} and operation in {"New", "Sum", "Sum224", "Sum256", "Sum384", "Sum512", "New224", "New384", "New512_224", "New512_256"}:
                algorithm, role = {"sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512", "md5": "MD5"}[package], "hash"
                if operation in {"Sum224", "New224"}:
                    algorithm = "SHA-224"
                elif operation in {"Sum384", "New384"}:
                    algorithm = "SHA-384"
            elif package == "hmac" and operation == "New" and args:
                digest = re.fullmatch(r"(\w+)\.New(?:384)?", args[0])
                if digest:
                    p = namespaces.get(digest.group(1))
                    algorithm = {"sha256": "HMAC-SHA-256", "sha512": "HMAC-SHA-512"}.get(p)
                    if algorithm and args[0].endswith("New384"):
                        algorithm = "HMAC-SHA-384"
                    role = "message-authentication"
            if algorithm:
                collector.add(algorithm, "static-call", f"line:{text.count(chr(10), 0, m.start()) + 1}",
                              f"Go {package}.{operation}" + (f"; statically inferred key size {bits} bits" if bits else ""),
                              key_bits=bits, role=role, detector="go-pattern", confidence="medium",
                              context={"operation": package + "." + operation},
                              caveats=["Bounded syntax and observed-call-site inference; general data flow, unseen callers and runtime execution are not proven."])
