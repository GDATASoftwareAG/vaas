<?php

namespace VaasSdk\Options;

class ForFileOptions
{
    private const DEFAULT_TIMEOUT = 300;
    private const DEFAULT_REQUEST_ID = null;
    
    public function __construct(
        public bool $useCache = true,
        public bool $useHashLookup = true,
        public int $timeout = self::DEFAULT_TIMEOUT,
        public ?string $vaasRequestId = self::DEFAULT_REQUEST_ID) {}

    public static function fromVaasOptions(VaasOptions $options): self
    {
        return new self(
            useCache: $options->useCache,
            useHashLookup: $options->useHashLookup,
            timeout: $options->timeout,
            vaasRequestId: self::DEFAULT_REQUEST_ID
        );
    }
}