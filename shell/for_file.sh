#!/bin/bash

source vaas.sh

if [ $# -eq 0 ]; then
    echo "Usage: $0 [FILE]..."
    exit 1
fi

VAAS_URL="https://gateway.staging.vaas.gdatasecurity.de"
TOKEN_URL="https://account-staging.gdata.de/realms/vaas-staging/protocol/openid-connect/token"

for file in "$@"; do
    for_file $VAAS_URL $TOKEN_URL $USER_NAME $PASSWORD $file
done
