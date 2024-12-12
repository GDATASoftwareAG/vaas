<?php

namespace VaasSdk\Options;

class ForSha256Options
{
    public bool $useCache;
    public bool $useHashLookup;
    public ?string $vaasRequestId;

    public function __construct(array $options = [])
    {
        $this->useCache = $options['useCache'] ?? true;
        $this->useHashLookup = $options['useHashLookup'] ?? true;
        $this->vaasRequestId = $options['vaasRequestId'] ?? null;
    }

    public static function default(): self
    {
        return new self();
    }
}