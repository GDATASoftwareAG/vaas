#!/usr/bin/env bash
set -e

VERSION=${VERSION:-"v1.0.4"}

echo "(*) Installing govulncheck..."

go install golang.org/x/vuln/cmd/govulncheck@${VERSION}

echo "Done!"
