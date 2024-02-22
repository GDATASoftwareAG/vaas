<?php

namespace VaasSdk\Message;

use Ramsey\Uuid\Rfc4122\UuidV4;

class VerdictRequestForUrl extends BaseVerdictRequest
{
    public string $url;

    public function __construct(string $url, string $uuid = null, string $SessionId)
    {
        parent::__construct(Kind::VerdictRequestForUrl, $uuid, $SessionId);
        $this->url = $url;
    }
}
