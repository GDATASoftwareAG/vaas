<?php

namespace VaasSdk\Options;

class VaasOptions
{
    public ?bool $useHashLookup;
    public ?bool $useCache;
    public string $url;
    public string $tokenUrl;

    public function __construct(
        ?bool $useHashLookup = null,
        ?bool $useCache = null,
        string $url = 'https://gateway.production.vaas.gdatasecurity.de/',
        string $tokenUrl = 'https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token'
    ) {
        $this->url = $url;
        $this->useHashLookup = $useHashLookup;
        $this->useCache = $useCache;
        $this->tokenUrl = $tokenUrl;
    }
}