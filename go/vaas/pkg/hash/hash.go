package hash

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

func CalculateSha256(data *os.File) (string, error) {
	sha256 := sha256.New()
	if _, err := io.Copy(sha256, data); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum(nil)), nil
}
