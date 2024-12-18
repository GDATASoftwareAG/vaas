<?php

namespace VaasSdk\Options;

class ForStreamOptions
{
    const DEFAULT_TIMEOUT = 300;
    const DEFAULT_REQUEST_ID = null;

    public function __construct(
        public bool $useHashLookup = true,
        public int $timeout = self::DEFAULT_TIMEOUT,
        public ?string $vaasRequestId = self::DEFAULT_REQUEST_ID) {}

    public static function fromVaasOptions(VaasOptions $options): self
    {
        return new self(
            $options->useCache,
            self::DEFAULT_TIMEOUT,
            self::DEFAULT_REQUEST_ID
        );
    }
}