<?php

namespace VaasSdk\Message;

use Ramsey\Uuid\Rfc4122\UuidV4;

class VerdictRequestForStream extends BaseVerdictRequest
{
    public function __construct(string $SessionId, string $uuid = null)
    {
        parent::__construct(Kind::VerdictRequestForStream, $uuid, $SessionId);
    }
}
