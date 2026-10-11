"""Exemplo sintetico para inspecao estatica; nao executar na demonstracao."""
from secrets import token_bytes as criar_chave
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

chave = criar_chave(32)
cifra = AESGCM(chave)
