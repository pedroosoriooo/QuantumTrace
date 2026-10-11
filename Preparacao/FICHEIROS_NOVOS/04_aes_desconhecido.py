"""A origem e o comprimento da chave nao constam deste exemplo."""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def preparar_cifra(chave):
    return AESGCM(chave)
