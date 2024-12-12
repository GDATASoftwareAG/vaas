<?php

namespace VaasSdk\Options;

class ForStreamOptions
{
    public bool $useHashLookup;
    public ?string $vaasRequestId;

    public function __construct(array $options = [])
    {
        $this->useHashLookup = $options['useHashLookup'] ?? true;
        $this->vaasRequestId = $options['vaasRequestId'] ?? null;
    }

    public static function default(): self
    {
        return new self();
    }
}