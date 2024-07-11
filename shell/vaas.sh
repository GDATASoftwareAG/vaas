#!/bin/bash

#set -x
#CURL_DEBUG="-v"

USER_AGENT="Shell SDK 0.1.0" 
CLIENT_ID="vaas-customer"

VAAS_VERDICT_UNKNOWN="Unknown"

function get_access_token() {
    local token_url=$1
    local user_name=$2
    local password=$3

    curl \
    $CURL_DEBUG \
    -s \
    --request POST \
    --url "$token_url" \
    --header "content-type: application/x-www-form-urlencoded" \
    --data "grant_type=password" \
    --data "username=$user_name" \
    --data "password=$password" \
    --data "client_id=$CLIENT_ID" \
    | jq -r .access_token
}

function for_file() {
    local vaas_url=${1%/}
    local token_url=$2
    local user_name=$3
    local password=$4
    local file=$5

    local output
    local status
    local location
    local body

    local token=$(get_access_token $token_url $user_name $password)
    local sha256=$(sha256sum "$file" | awk '{ print $1 }')

    output=$(curl \
    $CURL_DEBUG \
    -s \
    -w "%{http_code}" \
    -H "Authorization: Bearer $token" \
    -A "$USER_AGENT" \
    "${vaas_url}/files/${sha256}/report")
    status=${output: -3}
    body=${output::-3}

    if [ "$status" -ne 200 ]; then
        exit 1
    fi

    local verdict=$(echo $body | jq -r .verdict)
    if [ "$verdict" != "$VAAS_VERDICT_UNKNOWN" ]; then
        echo $verdict
        return
    fi

    output=$(curl -X PUT \
    $CURL_DEBUG \
    -s \
    -w "%{http_code}" \
    -H "Authorization: Bearer $token" \
    -A "$USER_AGENT" "${vaas_url}/files" \
    -i \
    --header "Content-Type:application/octet-stream" \
    --data-binary "@$file")
    status=${output: -3}
    body=${output::-3}

    if [ "$status" -ne 201 ]; then
        exit 1
    fi

    local relative_url=$(echo | grep -ioP '^location:\s*\K[^\r]*')

    output=$(curl \
    $CURL_DEBUG \
    -s \
    -H "Authorization: Bearer $token" \
    -A "$USER_AGENT" \
    "${vaas_url}${relative_url}/report")
   
   echo $output | jq -r .verdict
}
