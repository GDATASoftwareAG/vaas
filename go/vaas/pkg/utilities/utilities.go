package utilities

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

func Contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func ToSha256String(data *os.File) (string, error) {
	sha256 := sha256.New()
	if _, err := io.Copy(sha256, data); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum(nil)), nil
}
