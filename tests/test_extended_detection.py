"""Regression cases for realistic wrappers, AWS schemas and TLS provenance."""

import unittest

from quantumtrace.inventory import Collector
from quantumtrace.scanners import scan_config, scan_other_code, scan_python
from quantumtrace.tls import scan_tls_json


def findings(code, suffix=".py"):
    c = Collector("fixture", "0" * 64)
    (scan_python(code, c) if suffix == ".py" else scan_other_code(code, c, suffix))
    return c.findings


class ExtendedSourceTests(unittest.TestCase):
    def test_aesgcm_follows_observed_helper_call(self):
        code = 'import os\nfrom cryptography.hazmat.primitives.ciphers.aead import AESGCM\nN=32\ndef make_key():\n return os.urandom(N)\ndef encrypt(key, data):\n return AESGCM(key).encrypt(b"nonce", data, None)\nkey=make_key()\nencrypt(key,b"payload")\n'
        hits = findings(code)
        self.assertEqual([(h["algorithm"], h["key_bits"]) for h in hits], [("AES", 256)])
        self.assertEqual(hits[0]["context"]["mode"], "GCM")

    def test_conflicting_helper_calls_do_not_become_resilient(self):
        code = 'from cryptography.hazmat.primitives.ciphers.aead import AESGCM\ndef encrypt(key):\n return AESGCM(key)\nencrypt(b"x"*32)\nencrypt(b"x"*16)\n'
        self.assertEqual(findings(code)[0]["risk"], "unknown")

    def test_reassigned_key_is_unknown(self):
        code = 'from cryptography.hazmat.primitives.ciphers import algorithms\nkey=b"x"*32\nkey=read_unknown_key()\nalgorithms.AES(key)\n'
        self.assertEqual(findings(code)[0]["key_bits"], None)

    def test_helper_unknown_call_invalidates_default_inference(self):
        code = 'from cryptography.hazmat.primitives.ciphers import algorithms\ndef enc(key=b"x"*32):\n return algorithms.AES(key)\nenc()\nenc(external_key)\n'
        self.assertEqual(findings(code)[0]["risk"], "unknown")

    def test_kdf_records_output_length_without_claiming_security(self):
        code = 'from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC\nfrom cryptography.hazmat.primitives import hashes\nN=32\nPBKDF2HMAC(algorithm=hashes.SHA256(), length=N, salt=b"salt", iterations=600_000)\n'
        hit = next(h for h in findings(code) if h["role"] == "key-derivation")
        self.assertEqual(hit["algorithm"], "PBKDF2-HMAC-SHA-256")
        self.assertEqual(hit["key_bits"], 256)
        self.assertEqual(hit["context"]["iterations"], 600000)
        self.assertEqual(hit["risk"], "unknown")

    def test_hmac_digest_function_is_recognised(self):
        hits = findings('import hmac, hashlib\nhmac.new(key, data, hashlib.sha256)\n')
        self.assertEqual([h["algorithm"] for h in hits], ["HMAC-SHA-256"])

    def test_hmac_unknown_digest_namespace_is_not_guessed(self):
        self.assertEqual(findings('import hmac, custom\nhmac.new(key, data, custom.sha256)\n'), [])

    def test_java_constant_transform_and_literal_key(self):
        code = 'class App { private static final String T="AES/ECB/PKCS5Padding"; private static final byte[] K="0123456789ABCDEF".getBytes(StandardCharsets.UTF_8); public static void enc() { SecretKeySpec spec=new SecretKeySpec(K,"AES"); Cipher c=Cipher.getInstance(T); c.init(Cipher.ENCRYPT_MODE,spec); } }'
        hit = findings(code, ".java")[0]
        self.assertEqual(hit["key_bits"], 128)
        self.assertEqual(hit["risk"], "medium")
        self.assertIn("ECB", hit["classical_warning"])

    def test_java_string_containing_code_is_not_an_occurrence(self):
        self.assertEqual(findings('String s="Cipher.getInstance(\\"AES\\")";', ".java"), [])

    def test_java_scopes_do_not_share_rsa_size(self):
        code = 'class App { public static void a() { KeyPairGenerator g=KeyPairGenerator.getInstance("RSA"); g.initialize(1024); } public static void b() { KeyPairGenerator g=KeyPairGenerator.getInstance("RSA"); g.initialize(4096); } }'
        self.assertEqual([h["key_bits"] for h in findings(code, ".java")], [1024, 4096])

    def test_go_import_alias_and_key_length(self):
        code = 'package main\nimport a "crypto/aes"\nfunc main() {\n key := make([]byte, 32)\n a.NewCipher(key)\n}\n'
        self.assertEqual([(h["algorithm"], h["key_bits"]) for h in findings(code, ".go")], [("AES", 256)])

    def test_go_hmac_and_sha384_calls(self):
        code = 'import ("crypto/hmac"; "crypto/sha256"; "crypto/sha512")\nfunc main() {\n hmac.New(sha256.New,key)\n sha512.Sum384(data)\n}\n'
        self.assertEqual({h["algorithm"] for h in findings(code, ".go")}, {"HMAC-SHA-256", "SHA-384"})


class AWSConfigTests(unittest.TestCase):
    def scan(self, region, spec, usage="ENCRYPT_DECRYPT"):
        c = Collector("cloud", "0" * 64)
        scan_config({"Region": region, "Keys": [{"KeyId": "example", "KeyUsage": usage, "KeySpec": spec}]}, c)
        return c

    def test_symmetric_default_is_region_specific(self):
        eu = self.scan("eu-west-1", "SYMMETRIC_DEFAULT").findings[0]
        self.assertEqual((eu["algorithm"], eu["key_bits"], eu["risk"]), ("AES", 256, "resilient"))
        china = self.scan("cn-north-1", "SYMMETRIC_DEFAULT").findings[0]
        self.assertEqual((china["algorithm"], china["risk"]), ("SM4", "unknown"))
        self.assertEqual(self.scan(None, "SYMMETRIC_DEFAULT").findings, [])

    def test_ecc_key_role_and_curve_are_recorded(self):
        hit = self.scan("eu-west-1", "ECC_NIST_P384", "SIGN_VERIFY").findings[0]
        self.assertEqual((hit["algorithm"], hit["key_bits"], hit["role"]), ("EC", 384, "signature"))

    def test_kms_usage_arrays_are_recognised(self):
        c = Collector("cloud", "0" * 64)
        scan_config({"Region": "eu-west-1", "Keys": [{"KeyId": "example", "KeySpec": "RSA_2048", "SigningAlgorithms": ["RSASSA_PKCS1_V1_5_SHA_256"]}]}, c)
        self.assertEqual({h["algorithm"] for h in c.findings}, {"RSA", "SHA-256"})

    def test_unknown_policy_is_partial_and_never_resilient(self):
        c = Collector("cloud", "0" * 64)
        scan_config({"LoadBalancers": [{"Listeners": [{"SslPolicy": "ELBSecurityPolicy-Imaginary-PQ"}]}]}, c)
        self.assertEqual(c.findings, [])
        self.assertEqual(c.status, "partial")

    def test_known_policy_means_configured_not_negotiated(self):
        c = Collector("cloud", "0" * 64)
        scan_config({"LoadBalancers": [{"Listeners": [{"SslPolicy": "ELBSecurityPolicy-FS-1-2-Res-2020-10"}]}]}, c)
        self.assertEqual({h["observation"] for h in c.findings}, {"configured"})
        self.assertEqual({h["algorithm"] for h in c.findings}, {"AES", "ECDH", "ECDSA", "RSA", "SHA-256", "SHA-384"})


class ExtendedTLSTests(unittest.TestCase):
    def test_provenance_uses_frame_and_endpoint(self):
        c = Collector("capture", "0" * 64)
        layers = {"frame.number": "42", "tcp.stream": "8", "ip.src": "192.0.2.1", "tcp.srcport": "443", "tls.handshake.type": "2", "tls.handshake.version": "0x0303", "tls.handshake.extensions.supported_version": "0x0304", "tls.handshake.ciphersuite": "0x1302", "tls.handshake.extensions_key_share_group": "4588"}
        scan_tls_json([{"_source": {"layers": layers}}], c)
        hit = next(h for h in c.findings if h["algorithm"] == "ML-KEM")
        self.assertEqual(hit["context"]["frame"], "42")
        self.assertEqual(hit["context"]["protocol"], "TLS 1.3")
        self.assertTrue(hit["evidence"]["locator"].startswith("frame:42"))

    def test_hello_retry_does_not_claim_a_negotiated_key(self):
        c = Collector("capture", "0" * 64)
        layers = {"tls.handshake.type": "2", "tls.handshake.random": "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c", "tls.handshake.ciphersuite": "0x1302", "tls.handshake.extensions_key_share_group": "4588"}
        scan_tls_json([{"_source": {"layers": layers}}], c)
        self.assertEqual(c.findings, [])
        self.assertTrue(any("HelloRetryRequest" in w for w in c.warnings))
