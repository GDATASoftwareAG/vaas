<?php

namespace VaasSdk\Options;

class ForSha256Options
{
    private const DEFAULT_REQUEST_ID = null;

    public function __construct(
        public bool $useCache = true,
        public bool $useHashLookup = true,
        public ?string $vaasRequestId = self::DEFAULT_REQUEST_ID) {}

    public static function fromVaasOptions(VaasOptions $options): self
    {
        return new self(
            $options->useCache,
            $options->useHashLookup,
            self::DEFAULT_REQUEST_ID
        );
    }
}