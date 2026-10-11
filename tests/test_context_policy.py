"""Semantic checks for context-aware assessments and conservative unknowns."""

import unittest

from quantumtrace.inventory import Collector, build_priorities, make_report
from quantumtrace.policy import classify, parse_label
from quantumtrace.scanners import scan_config, scan_other_code, scan_python


class ContextPolicyTests(unittest.TestCase):
    def test_same_hash_has_different_collision_and_preimage_tiers(self):
        collision = classify("SHA-256", context={"hash_use": "signature-digest"})
        preimage = classify("SHA-256", context={"hash_use": "preimage-resistance"})
        self.assertEqual((collision["risk"], preimage["risk"]), ("medium", "resilient"))
        self.assertEqual(preimage["assessment"]["query_exponent_bits"], 128)
        self.assertTrue(collision["assessment"]["assumptions"])
        self.assertEqual(classify("SHA-256")["review_reason"], "missing_context")

    def test_sha384_meets_target_even_using_weaker_generic_model(self):
        hit = classify("SHA-384")
        self.assertEqual(hit["risk"], "resilient")
        self.assertEqual(hit["assessment"]["query_exponent_bits"], 128)
        self.assertIn("conservative", hit["assessment"]["model"])

    def test_tls_hash_model_is_explicitly_conservative(self):
        c = Collector("hello.json", "0" * 64)
        scan_config({"CipherSuite": "TLS_AES_128_GCM_SHA256"}, c)
        hit = next(f for f in c.findings if f["algorithm"] == "SHA-256")
        self.assertEqual(hit["risk"], "medium")
        self.assertTrue(any("HKDF" in a for a in hit["assessment"]["assumptions"]))

    def test_exact_ietf_chacha_suite_establishes_size_but_bare_name_does_not(self):
        full = next(f for f in parse_label("TLS_CHACHA20_POLY1305_SHA256") if f["algorithm"] == "ChaCha20")
        self.assertEqual(full["key_bits"], 256)
        self.assertEqual(classify(full["algorithm"], full["key_bits"])["risk"], "resilient")
        self.assertEqual(classify("ChaCha20")["review_reason"], "missing_parameters")

    def test_oaep_hash_is_a_construction_policy_gap_not_unidentified_crypto(self):
        c = Collector("kms.json", "0" * 64)
        scan_config({"Region": "eu-west-1", "Keys": [{"KeyId": "test", "KeySpec": "RSA_2048", "KeyUsage": "ENCRYPT_DECRYPT", "EncryptionAlgorithms": ["RSAES_OAEP_SHA_256"]}]}, c)
        hit = next(f for f in c.findings if f["algorithm"] == "SHA-256")
        self.assertEqual(hit["review_reason"], "policy_gap")
        self.assertEqual(hit["context"]["hash_use"], "oaep-mask-generation")
        self.assertTrue(any(f["algorithm"] == "RSA" and f["risk"] == "critical" for f in c.findings))

    def test_password_kdf_does_not_turn_output_length_into_entropy(self):
        hit = classify("PBKDF2-HMAC-SHA-256", 256, context={"iterations": 600000, "salt_bits": 128})
        self.assertEqual(hit["risk"], "unknown")
        self.assertTrue(any("entropy" in p for p in hit["missing_information"]))
        self.assertTrue(any("generation" in p for p in hit["missing_information"]))

    def test_java_kdf_follows_correct_spec_and_keeps_password_unknown(self):
        code = '''class App { public static byte[] derive(char[] password) throws Exception {
          KeySpec unrelated = new PBEKeySpec(password, new byte[4], 100, 128);
          byte[] salt = new byte[16];
          KeySpec selected = new PBEKeySpec(password, salt, 600_000, 256);
          SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
          return factory.generateSecret(selected).getEncoded();
        } }'''
        c = Collector("input.java", "0" * 64)
        scan_other_code(code, c, ".java")
        hit = c.findings[0]
        self.assertEqual((hit["key_bits"], hit["context"]["iterations"], hit["context"]["salt_bits"]), (256, 600000, 128))
        self.assertEqual(hit["risk"], "unknown")

    def test_python_pbkdf2_digest_is_a_component_and_parameters_remain_visible(self):
        c = Collector("input.py", "0" * 64)
        scan_python('from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC\nfrom cryptography.hazmat.primitives import hashes\nPBKDF2HMAC(algorithm=hashes.SHA256(), length=32, iterations=600_000, salt=b"0123456789abcdef")', c)
        parent = next(f for f in c.findings if f["algorithm"].startswith("PBKDF2"))
        digest = next(f for f in c.findings if f["algorithm"] == "SHA-256")
        self.assertEqual(parent["risk"], "unknown")
        self.assertEqual(parent["context"]["salt_bits"], 128)
        self.assertEqual(digest["context"]["hash_use"], "key-derivation-component")



class PriorityTests(unittest.TestCase):
    def finding(self, source, algorithm, observation="configured", bits=None, context=None, locator="/key"):
        c = Collector(source, "0" * 64)
        c.add(algorithm, observation, locator, "Supported test evidence", bits, context=context)
        return c.findings[0]

    def test_offered_classical_key_is_inventory_only_and_has_no_index(self):
        f = self.finding("tls.json", "RSA", "offered", 2048)
        report = make_report([f], [], [])
        actions = report["priorities"]["groups"][0]["actions"]
        self.assertEqual([a["kind"] for a in actions], ["offered-capability"])
        self.assertIsNone(report["summary"]["quantum_risk_score"])
        self.assertEqual(report["summary"]["offered_findings"], 1)

    def test_selected_configured_and_static_evidence_have_distinct_order(self):
        findings = [self.finding("a.py", "RSA", "static-call", 3072),
                    self.finding("b.json", "RSA", "configured", 3072),
                    self.finding("z.pcap", "ECDH", "negotiated", 256)]
        groups = build_priorities(findings)["groups"]
        self.assertEqual([g["source"] for g in groups], ["z.pcap", "b.json", "a.py"])
        self.assertIn("runtime", groups[1]["actions"][0]["reason"])

    def test_hybrid_components_stay_together_without_direct_migration(self):
        context = {"session": "7", "event": "server_hello", "mechanism": "X25519MLKEM768", "hybrid_components": True}
        findings = [self.finding("tls.pcap", "X25519", "negotiated", context=context),
                    self.finding("tls.pcap", "ML-KEM", "negotiated", context=context)]
        group = build_priorities(findings)["groups"][0]
        self.assertEqual([f["risk"] for f in findings], ["critical", "resilient"])
        self.assertEqual([a["kind"] for a in group["actions"]], ["hybrid-review"])
        self.assertEqual(len(group["actions"][0]["finding_ids"]), 2)
        self.assertIn("does not prove", findings[0]["explanation"])
        self.assertIn("Do not replace", findings[0]["recommendation"])

    def test_unknown_aes_requests_parameters_without_safe_inference(self):
        f = self.finding("unknown.py", "AES", "static-call")
        action = build_priorities([f])["groups"][0]["actions"][0]
        self.assertEqual((f["risk"], action["kind"]), ("unknown", "missing-information"))
        self.assertIn("key length", action["next_step"])

    def test_hash_action_keeps_project_model_and_practical_limits(self):
        f = self.finding("tls.json", "SHA-256", "negotiated", context={"hash_use": "tls-suite-component"})
        action = build_priorities([f])["groups"][0]["actions"][0]
        self.assertEqual(action["kind"], "hash-policy-review")
        self.assertIn("not a NIST category", action["reason"])
        self.assertIn("practical attack", action["reason"])

    def test_cloud_assets_are_separate_resources_in_the_same_file(self):
        findings = [self.finding("kms.json", "RSA", bits=2048, context={"asset_id": "key-a"}),
                    self.finding("kms.json", "AES", bits=256, context={"asset_id": "key-b"})]
        groups = build_priorities(findings)["groups"]
        self.assertEqual(len(groups), 2)
        self.assertEqual({g["resource"] for g in groups}, {"key-a", "key-b"})
        self.assertTrue(all(g["resource_kind"] == "cloud-resource" for g in groups))

    def test_same_stream_number_in_different_files_is_not_merged(self):
        findings = [self.finding(source, "ECDH", "negotiated", context={"session": "1"})
                    for source in ("first.pcap", "second.pcap")]
        self.assertEqual(build_priorities(findings)["group_count"], 2)

    def test_every_observation_can_be_inspected_and_offers_stay_separate(self):
        findings = [self.finding("one.json", "RSA", bits=2048),
                    self.finding("one.json", "AES", bits=256),
                    self.finding("one.json", "RSA", "offered", 3072)]
        group = build_priorities(findings)["groups"][0]
        ids = [id for a in group["actions"] for id in a["finding_ids"]]
        self.assertCountEqual(ids, [f["id"] for f in findings])
        self.assertEqual(group["risk_counts"], {"critical": 1, "resilient": 1})
        self.assertEqual(group["evidence_counts"]["offered"], 1)
        self.assertEqual(group["actions"][-1]["kind"], "offered-capability")

    def test_resource_and_action_order_is_deterministic(self):
        findings = [self.finding("b.json", "AES", bits=256),
                    self.finding("a.json", "RSA", bits=2048),
                    self.finding("a.json", "AES", bits=128)]
        self.assertEqual(build_priorities(findings), build_priorities(list(reversed(findings))))

    def test_legacy_html_derives_priorities_without_mutating_original_report(self):
        from quantumtrace.report import render_html
        import json
        import re
        report = make_report([self.finding("code.py", "RSA", "static-call", 3072)], [], [])
        report.pop("priorities")
        original = json.dumps(report, sort_keys=True)
        html = render_html(report)
        embedded = json.loads(re.search(r'<script type="application/json" id="data">(.*?)</script>', html, re.S).group(1))
        self.assertEqual(embedded["priorities"]["group_count"], 1)
        self.assertEqual(embedded["summary"]["quantum_risk_score"], 100)
        self.assertEqual(json.dumps(report, sort_keys=True), original)

    def test_empty_inventory_has_no_synthetic_priority(self):
        report = make_report([], [], [])
        self.assertEqual(report["priorities"]["groups"], [])
        self.assertIsNone(report["summary"]["quantum_risk_score"])

    def test_same_resource_keeps_selected_and_configured_actions_distinct(self):
        context = {"asset_id": "resource-a"}
        findings = [self.finding("resource.json", "RSA", "configured", 2048, context),
                    self.finding("resource.json", "RSA", "negotiated", 2048, context)]
        group = build_priorities(findings)["groups"][0]
        self.assertEqual([a["observation"] for a in group["actions"]], ["negotiated", "configured"])
        self.assertEqual(group["evidence_counts"], {"configured": 1, "negotiated": 1})

if __name__ == "__main__":
    unittest.main()
