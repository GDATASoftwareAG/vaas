<?php

namespace VaasSdk\Options;

class ForUrlOptions
{
    public function __construct(
        public bool $useHashLookup = true,
        public ?string $vaasRequestId = null) {}

    public static function default(): self
    {
        return new self();
    }
}