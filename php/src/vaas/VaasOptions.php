<?php

namespace VaasSdk;

class VaasOptions
{
    public bool $UseCache = true;
    public bool $UseHashLookup = true;

    public function __construct(bool $useCache = true, bool $useHashLookup = true)
    {
        $this->UseCache = $useCache;
        $this->UseHashLookup = $useHashLookup;
    }
}