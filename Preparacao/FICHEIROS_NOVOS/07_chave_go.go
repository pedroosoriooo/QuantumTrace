package main

import (
    "crypto/aes"
    "crypto/rand"
)

// Exemplo sintetico para inspecao; nao executar na demonstracao.
func main() {
    chave := make([]byte, 16)
    rand.Read(chave)
    aes.NewCipher(chave)
}
