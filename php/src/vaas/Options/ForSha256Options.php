<?php

namespace VaasSdk\Options;

class ForSha256Options
{
    public function __construct(
        public bool $useCache = true,
        public bool $useHashLookup = true,
        public ?string $vaasRequestId = null) {}

    public static function default(): self
    {
        return new self();
    }
}