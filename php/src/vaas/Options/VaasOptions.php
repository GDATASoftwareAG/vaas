<?php

namespace VaasSdk\Options;

class VaasOptions
{
    /**
     * Options to control the behavior of the VaaS SDK
     * @param bool|null $useHashLookup Use the G DATA cloud to check the hash of the file
     * @param bool|null $useCache Use the cache to store the hash of the file
     * @param string $vaasUrl The URL of the VaaS backend to use either the G DATA cloud or a self-hosted instance
     * @param int $timeout The timeout in seconds for the file upload to the VaaS backend
     */
    public function __construct(
        public bool  $useHashLookup = true,
        public bool  $useCache = true,
        public string $vaasUrl = 'https://gateway.production.vaas.gdatasecurity.de',
        public int    $timeout = 300
    ) {}
}