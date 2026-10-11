"""SYNTHETIC fixture: parsed as source, never executed by QuantumTrace."""

import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import algorithms

# Comment mentioning RSA-1024 and AES-128 is not a finding.
description = "RSA.generate(1024) is just text, not an executed call."


def example_calls(key_material):
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cipher = algorithms.AES(key_material)  # Variable key size remains unknown.
    explicit_demo_cipher = algorithms.AES(b"\x00" * 32)  # Synthetic key, not a secure key-generation example.
    legacy_digest = hashlib.sha1(b"synthetic input")
    return signing_key, cipher, explicit_demo_cipher, legacy_digest
