// SYNTHETIC static-analysis fixture.
package demo

import (
    "crypto/rsa"
    "crypto/rand"
    "crypto/sha1"
)

func example() {
    rsa.GenerateKey(rand.Reader, 2048)
    sha1.New()
}
