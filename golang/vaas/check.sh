#!/bin/sh

# pkg="lexer"

go fmt ./pkg/"$1"/*.go
govulncheck golang/vaas/...       
golangci-lint run ./pkg/"$1"/*.go