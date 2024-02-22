<?php

namespace VaasSdk\Message;

use Ramsey\Uuid\Rfc4122\UuidV4;

class VerdictRequest extends BaseVerdictRequest
{
    public string $sha256;

    public function __construct(string $sha256, string $uuid = null, string $SessionId)
    {
        parent::__construct($uuid, $SessionId);
        $this->kind = new Kind(Kind::VERDICT_REQUEST);
        $this->sha256 = $sha256;
    }
}
