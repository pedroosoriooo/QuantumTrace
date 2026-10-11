"""Manual expectations for the supplied synthetic starter, not official truth.

The set checks assert specific known primitives and parameters in all 24 source
files. They do not measure exhaustive occurrence recall or general accuracy.
"""

import os
import shutil
import unittest
from pathlib import Path

from quantumtrace.inventory import scan_path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" if (ROOT / "data").is_dir() else ROOT.parent / "quantumtrace-starter"
if os.environ.get("QUANTUMTRACE_TEST_DATA"):
    DATA = Path(os.environ["QUANTUMTRACE_TEST_DATA"])
EXPECTED = {
    "python/legacy_accounts.py": {"MD5"}, "python/update_feed.py": {"SHA-1"},
    "python/license_token.py": {"RSA", "SHA-1"}, "python/webhook_signature.py": {"Ed25519"},
    "python/secure_transfer.py": {"AES"}, "python/report_export.py": {"AES"},
    "python/member_credentials.py": {"PBKDF2-HMAC-SHA-256", "SHA-256"},
    "python/artifact_manifest.py": {"HMAC-SHA-256", "SHA-384"},
    "java/CustomerDirectory.java": {"MD5"}, "java/PatchFeed.java": {"SHA-1"},
    "java/ReceiptSigner.java": {"RSA", "SHA-1"}, "java/DeviceAttestation.java": {"Ed25519"},
    "java/SessionCipher.java": {"AES"}, "java/BatchExporter.java": {"AES"},
    "java/IdentityVault.java": {"PBKDF2-HMAC-SHA-256"}, "java/ConfigSync.java": {"SHA-384", "HMAC-SHA-256"},
    "go/member-directory/main.go": {"MD5"}, "go/release-feed/main.go": {"SHA-1"},
    "go/invoice-service/main.go": {"RSA", "SHA-1"}, "go/agent-enrollment/main.go": {"Ed25519"},
    "go/telemetry-relay/main.go": {"AES"}, "go/batch-pipeline/main.go": {"AES"},
    "go/auth-gateway/main.go": {"HMAC-SHA-256"}, "go/config-sync/main.go": {"SHA-384", "HMAC-SHA-256"},
}


@unittest.skipUnless(DATA.is_dir(), "Partner starter dataset is not bundled")
class StarterDatasetTests(unittest.TestCase):
    def test_known_algorithm_sets_in_all_24_source_files(self):
        report = scan_path(DATA / "sample-repos")
        self.assertEqual(report["summary"]["error_files"], 0)
        for source, expected in EXPECTED.items():
            with self.subTest(source=source):
                actual = {h["algorithm"] for h in report["findings"] if h["evidence"]["source"] == source}
                self.assertEqual(actual, expected)

    def test_aes_key_lengths_in_six_source_examples(self):
        report = scan_path(DATA / "sample-repos")
        for source, size in {
            "python/secure_transfer.py": 256, "python/report_export.py": 128,
            "java/SessionCipher.java": 256, "java/BatchExporter.java": 128,
            "go/telemetry-relay/main.go": 256, "go/batch-pipeline/main.go": 128,
        }.items():
            with self.subTest(source=source):
                hits = [h for h in report["findings"] if h["evidence"]["source"] == source and h["algorithm"] == "AES"]
                self.assertTrue(hits)
                self.assertEqual({h["key_bits"] for h in hits}, {size})

    def test_cloud_keys_and_policy_context(self):
        report = scan_path(DATA / "cloud-posture")
        keys = [h for h in report["findings"] if h["evidence"]["source"] == "kms_key_inventory.json" and h["evidence"]["locator"].endswith("/KeySpec")]
        self.assertEqual(len(keys), 10)
        self.assertEqual(sum(h["algorithm"] == "AES" and h["key_bits"] == 256 for h in keys), 4)
        policies = {h["context"]["asset_id"] for h in report["findings"] if h["evidence"]["detector"] == "aws-elb-policy"}
        self.assertEqual(len(policies), 5)

    @unittest.skipUnless(shutil.which("tshark"), "TShark optional integration test")
    def test_capture_has_97_hello_pairs_and_seven_hybrid_negotiations(self):
        report = scan_path(DATA / "network-capture" / "network.pcap")
        self.assertEqual(report["summary"]["partial_files"], 0)
        self.assertEqual(report["summary"]["error_files"], 0)
        offers = {h["context"]["session"] for h in report["findings"] if h["observation"] == "offered"}
        choices = {h["context"]["session"] for h in report["findings"] if h["observation"] == "negotiated"}
        self.assertEqual(len(offers), 97)
        self.assertEqual(offers, choices)
        hybrids = {h["context"]["session"] for h in report["findings"] if h["algorithm"] == "ML-KEM" and h["observation"] == "negotiated"}
        self.assertEqual(len(hybrids), 7)
