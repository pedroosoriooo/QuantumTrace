"""Exemplo sintetico para inspecao estatica; nao executar na demonstracao."""
from secrets import token_bytes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

chave = token_bytes(16)
cifra = AESGCM(chave)
