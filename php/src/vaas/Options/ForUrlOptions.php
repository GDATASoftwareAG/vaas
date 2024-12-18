<?php

namespace VaasSdk\Options;

class ForUrlOptions
{
    const DEFAULT_REQUEST_ID = null;

    public function __construct(
        public bool $useHashLookup = true,
        public ?string $vaasRequestId = self::DEFAULT_REQUEST_ID) {}

    public static function fromVaasOptions(VaasOptions $options): self
    {
        return new self(
            $options->useHashLookup,
            self::DEFAULT_REQUEST_ID
        );
    }
}