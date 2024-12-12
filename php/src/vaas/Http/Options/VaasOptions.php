<?php

namespace VaasSdk\Options;

use VaasSdk\Authentication\TokenRequest;

class VaasOptions
{
    public TokenRequest $credentials;
    public ?bool $useHashLookup;
    public ?bool $useCache;
    public string $url;
    public string $tokenUrl;

    public function __construct(
        TokenRequest $credentials,
        ?bool $useHashLookup = null,
        ?bool $useCache = null,
        string $url = 'https://gateway.production.vaas.gdatasecurity.de/',
        string $tokenUrl = 'https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token'
    ) {
        $this->url = $url;
        $this->useHashLookup = $useHashLookup;
        $this->useCache = $useCache;
        $this->tokenUrl = $tokenUrl;
        $this->credentials = $credentials;
    }
}