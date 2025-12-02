<?php

namespace VaasSdk\Options;

use Amp\File\FilesystemDriver;

class ForFileOptions
{
    public const DEFAULT_TIMEOUT = 300;
    public const DEFAULT_REQUEST_ID = null;
    
    public function __construct(
        public bool        $useCache = true,
        public bool        $useHashLookup = true,
        public int         $timeout = self::DEFAULT_TIMEOUT,
		public ?FilesystemDriver $filesystemDriver = null,
        public ?string     $vaasRequestId = self::DEFAULT_REQUEST_ID) {}

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