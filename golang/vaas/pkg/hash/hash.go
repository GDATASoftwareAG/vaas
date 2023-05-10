package hash

import (
	"crypto/sha256"
	"fmt"
	"io"
)

func CalculateSha256(data io.Reader) (string, error) {
	sha := sha256.New()
	if _, err := io.Copy(sha, data); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha.Sum(nil)), nil
}
