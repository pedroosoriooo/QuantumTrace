"""Behavioral checks: false positives, evidence provenance and uncertainty."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from quantumtrace.inventory import Collector, make_report, scan_path
from quantumtrace.policy import classify, parse_label
from quantumtrace.report import write_reports
from quantumtrace.scanners import scan_config, scan_other_code, scan_python, scan_certificate
from quantumtrace.tls import scan_tls_json, scan_capture


def collector():
    return Collector("fixture", "0" * 64)


class PolicyTests(unittest.TestCase):
    def test_aes_requires_known_valid_size(self):
        for size in [None, 0, 64, 512]:
            self.assertEqual(classify("AES", size)["risk"], "unknown")
        self.assertEqual(classify("AES", 128)["risk"], "medium")
        self.assertEqual(classify("AES", 256)["risk"], "resilient")

    def test_pqc_parameter_is_not_key_length(self):
        self.assertEqual(parse_label("ML-KEM-768")[0]["key_bits"], None)
        self.assertEqual(parse_label("ML-KEM-768")[0]["algorithm"], "ML-KEM")

    def test_no_classical_dsa_inside_pqc_signature_name(self):
        for name in ["ML-DSA-65", "SLH-DSA-SHA2-128s"]:
            self.assertEqual(len(parse_label(name)), 1)
            self.assertNotEqual(parse_label(name)[0]["algorithm"], "DSA")

    def test_kyber_name_does_not_certify_final_standard(self):
        self.assertEqual(classify("Kyber")["risk"], "unknown")

    def test_tls_suite_identifies_separate_primitives(self):
        items = parse_label("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
        self.assertEqual({i["algorithm"] for i in items}, {"ECDH", "RSA", "AES", "SHA-384"})
        self.assertEqual(next(i for i in items if i["algorithm"] == "AES")["key_bits"], 256)

    def test_ecdh_is_not_also_dh(self):
        self.assertEqual([i["algorithm"] for i in parse_label("ECDHE")], ["ECDH"])

    def test_hybrid_name_preserves_both_components(self):
        self.assertEqual({i["algorithm"] for i in parse_label("X25519MLKEM768", "key-establishment")}, {"X25519", "ML-KEM"})


class ConfigTests(unittest.TestCase):
    def test_prose_and_secrets_are_not_crypto_evidence(self):
        c = collector()
        scan_config({"description": "RSA and AES-256", "private_key": "SECRET_DATA", "algorithm": "RSA", "key_size": 2048}, c)
        self.assertEqual(len(c.findings), 1)
        self.assertEqual(c.findings[0]["key_bits"], 2048)
        self.assertNotIn("SECRET_DATA", json.dumps(c.findings))

    def test_unknown_size_does_not_borrow_sibling_size(self):
        c = collector()
        scan_config({"a": {"algorithm": "AES", "key_bits": 256}, "b": {"algorithm": "AES"}}, c)
        self.assertEqual([f["risk"] for f in c.findings], ["resilient", "unknown"])

    def test_json_pointer_escaping(self):
        c = collector()
        scan_config({"a/b~c": {"algorithm": "RSA"}}, c)
        self.assertEqual(c.findings[0]["evidence"]["locator"], "/a~1b~0c/algorithm")

    def test_unmapped_label_is_explicit(self):
        c = collector()
        scan_config({"algorithm": "unrecognised-primitive"}, c)
        self.assertEqual(c.findings, [])
        self.assertTrue(c.warnings)


class SourceTests(unittest.TestCase):
    def test_python_comments_strings_and_imports_are_not_calls(self):
        c = collector()
        scan_python('from cryptography.hazmat.primitives.asymmetric import rsa\n# rsa.generate_private_key(key_size=1024)\ns = "rsa.generate_private_key(key_size=1024)"\n', c)
        self.assertEqual(c.findings, [])

    def test_python_alias_and_positional_rsa_size(self):
        c = collector()
        scan_python('from cryptography.hazmat.primitives.asymmetric import rsa as r\nr.generate_private_key(65537, 3072)\n', c)
        self.assertEqual(c.findings[0]["algorithm"], "RSA")
        self.assertEqual(c.findings[0]["key_bits"], 3072)
        self.assertEqual(c.findings[0]["observation"], "static-call")

    def test_python_never_executes_input(self):
        with tempfile.TemporaryDirectory() as d:
            marker = Path(d) / "must-not-exist"
            c = collector()
            scan_python(f'open({str(marker)!r}, "w").write("executed")\n', c)
            self.assertFalse(marker.exists())

    def test_aes_literal_and_dynamic_key_differ(self):
        c = collector()
        scan_python('from cryptography.hazmat.primitives.ciphers import algorithms\nalgorithms.AES(b"x" * 32)\nalgorithms.AES(key)\n', c)
        self.assertEqual([f["key_bits"] for f in c.findings], [256, None])
        self.assertEqual([f["risk"] for f in c.findings], ["resilient", "unknown"])

    def test_non_crypto_namespace_is_not_detected(self):
        c = collector()
        scan_python('class RSA: pass\nRSA.generate(2048)\n', c)
        self.assertEqual(c.findings, [])

    def test_java_comments_are_ignored(self):
        c = collector()
        scan_other_code('// Cipher.getInstance("AES");\n/* MessageDigest.getInstance("SHA-1"); */\nCipher.getInstance("AES/GCM/NoPadding");', c, ".java")
        self.assertEqual(len(c.findings), 1)
        self.assertEqual(c.findings[0]["risk"], "unknown")

    def test_go_comments_and_literal_calls_are_ignored(self):
        c = collector()
        scan_other_code('// rsa.GenerateKey(rand.Reader, 1024)\ns := "rsa.GenerateKey(rand.Reader, 1024)"\nrsa.GenerateKey(rand.Reader, 2048)', c, ".go")
        self.assertEqual(len(c.findings), 1)
        self.assertEqual(c.findings[0]["key_bits"], 2048)


class TLSTests(unittest.TestCase):
    def test_offered_does_not_mean_negotiated_or_scored(self):
        c = collector()
        scan_tls_json({"format": "quantumtrace.tls/1.0", "events": [{"type": "client_hello", "signature_schemes": ["RSA_PSS_SHA256"]}]}, c)
        report = make_report(c.findings, [], [])
        self.assertEqual(report["summary"]["rated_findings"], 0)
        self.assertIsNone(report["summary"]["quantum_risk_score"])
        self.assertTrue(all(f["observation"] == "offered" for f in c.findings))

    def test_aes256_serverhello_does_not_prove_pqc(self):
        c = collector()
        scan_tls_json({"format": "quantumtrace.tls/1.0", "events": [{"type": "server_hello", "cipher_suite": "TLS_AES_256_GCM_SHA384", "key_share_group": "X25519"}]}, c)
        self.assertEqual(next(f for f in c.findings if f["algorithm"] == "X25519")["risk"], "critical")
        self.assertTrue(c.warnings)

    def test_numeric_hybrid_group(self):
        c = collector()
        scan_tls_json({"format": "quantumtrace.tls/1.0", "events": [{"type": "server_hello", "cipher_suite": "0x1302", "key_share_group": "0x11ec"}]}, c)
        pqc = next(f for f in c.findings if f["algorithm"] == "ML-KEM")
        self.assertTrue(pqc["context"]["hybrid_components"])
        self.assertEqual(pqc["risk"], "resilient")

    def test_tshark_array_fields_are_retained(self):
        c = collector()
        packets = [{"_source": {"layers": {"tcp": {"tcp.stream": "7"}, "tls": {"tls.handshake.type": "1", "tls.handshake.ciphersuite": ["0x1301", "0x1302"]}}}}]
        self.assertTrue(scan_tls_json(packets, c))
        self.assertEqual({f["key_bits"] for f in c.findings if f["algorithm"] == "AES"}, {128, 256})

    def test_mixed_handshake_packet_is_not_misclassified(self):
        c = collector()
        scan_tls_json([{"_source": {"layers": {"tls.handshake.type": ["1", "2"], "tls.handshake.ciphersuite": ["0x1301", "0x1302"]}}}], c)
        self.assertEqual(c.findings, [])
        self.assertTrue(c.warnings)

    def test_unknown_identifier_does_not_become_resilient(self):
        c = collector()
        scan_tls_json({"format": "quantumtrace.tls/1.0", "events": [{"type": "server_hello", "cipher_suite": "0xFFFF", "key_share_group": 65535}]}, c)
        self.assertEqual(c.findings, [])
        self.assertTrue(c.warnings)

    def test_missing_tshark_is_incomplete_not_safe(self):
        c = collector()
        with patch("quantumtrace.tls.shutil.which", return_value=None):
            scan_capture(Path("fixture.pcap"), c)
        self.assertEqual(c.status, "partial")
        self.assertEqual(c.findings, [])
        self.assertTrue(c.warnings)


class IntegrationTests(unittest.TestCase):
    def test_malformed_file_does_not_hide_other_results(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "good.json").write_text('{"algorithm":"RSA"}')
            (root / "bad.json").write_text('{"private_key":"SECRET",')
            (root / "unknown.bin").write_bytes(b"AES RSA")
            r = scan_path(root)
            self.assertEqual(r["summary"]["error_files"], 1)
            self.assertEqual(r["summary"]["unsupported_files"], 1)
            self.assertEqual(r["summary"]["total_findings"], 1)
            self.assertNotIn("SECRET", json.dumps(r))

    def test_empty_input_is_not_a_zero_risk_claim(self):
        with tempfile.TemporaryDirectory() as d:
            r = scan_path(d)
            self.assertIsNone(r["summary"]["quantum_risk_score"])

    def test_html_cannot_close_data_tag_with_filename(self):
        c = collector()
        c.source = '</script><img src=x onerror="alert(1)">'
        c.add("RSA", "configured", "/algorithm", "RSA")
        with tempfile.TemporaryDirectory() as d:
            html, inventory = write_reports(make_report(c.findings, [], []), d)
            text = html.read_text()
            self.assertNotIn(c.source, text)
            self.assertIn("\\u003c/script\\u003e", text)
            self.assertEqual(json.loads(inventory.read_text())["findings"][0]["algorithm"], "RSA")

    def test_demo_has_no_file_errors(self):
        samples = Path(__file__).resolve().parents[1] / "samples"
        r = scan_path(samples)
        self.assertEqual(r["summary"]["analysed_files"], 5)
        self.assertEqual(r["summary"]["error_files"], 0)
        self.assertTrue(any(f["algorithm"] == "ML-KEM" for f in r["findings"]))


try:
    import cryptography
except ImportError:
    cryptography = None


@unittest.skipIf(cryptography is None, "Optional cryptography dependency is absent")
class CertificateTests(unittest.TestCase):
    def test_public_key_is_parsed_without_exposing_material(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        c = collector()
        scan_certificate(public, c)
        self.assertEqual(c.findings[0]["algorithm"], "RSA")
        self.assertEqual(c.findings[0]["key_bits"], 2048)
        self.assertNotIn("BEGIN PUBLIC KEY", json.dumps(c.findings))

    def test_private_keys_are_not_parsed(self):
        c = collector()
        scan_certificate(b"-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----", c)
        self.assertEqual(c.findings, [])
        self.assertTrue(c.warnings)


if __name__ == "__main__":
    unittest.main()
