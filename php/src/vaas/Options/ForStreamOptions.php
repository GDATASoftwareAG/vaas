<?php

namespace VaasSdk\Options;

class ForStreamOptions
{
    public function __construct(
        public bool $useHashLookup = true,
        public int $timeout = 300,
        public ?string $vaasRequestId = null) {}

    public static function default(): self
    {
        return new self();
    }
}