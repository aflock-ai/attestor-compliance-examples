// Package insecure is a deliberate fixture for gosec scanning.
//
// It contains patterns gosec is known to flag so the example can produce a
// real, non-empty SARIF report. Do NOT use any of this code outside of
// gosec validation.
package insecure

import (
	"crypto/md5"
	"fmt"
	"math/rand"
)

// WeakToken uses math/rand for a security-sensitive value.
// gosec rule G404: Insecure random number source (rand).
func WeakToken() int {
	return rand.Int() //nolint:gosec // intentional finding for fixture
}

// WeakHash uses MD5 for hashing.
// gosec rule G401: Use of weak cryptographic primitive.
// gosec rule G501: Blocklisted import crypto/md5.
func WeakHash(data []byte) string {
	h := md5.New() //nolint:gosec // intentional finding for fixture
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil))
}
