// Package hash provides utility functions for hashing data using the SHA-256 algorithm.
package hash

import (
	"crypto/sha256"
	"fmt"
	"io"
)

// CalculateSha256 calculates the SHA-256 hash of the data from the given io.Reader.
// It returns the hexadecimal representation of the hash and any error encountered during the process.
func CalculateSha256(data io.Reader) (string, error) {
	sha := sha256.New()
	if _, err := io.Copy(sha, data); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha.Sum(nil)), nil
}
