"""Exemplo sintetico: o comprimento nao elimina a exposicao a Shor."""
from cryptography.hazmat.primitives.asymmetric import rsa as gerador

chave = gerador.generate_private_key(public_exponent=65537, key_size=3072)
