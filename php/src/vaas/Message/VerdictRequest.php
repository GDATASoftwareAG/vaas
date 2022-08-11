<?php

namespace VaasSdk\Message;

use Ramsey\Uuid\Rfc4122\UuidV4;

class VerdictRequest
{
    public string $sha256;
    public string $guid;
    public Kind $kind;
    public string $session_id;

    public function __construct(string $sha256, string $uuid = null, string $SessionId)
    {
        $this->kind = new Kind(Kind::VERDICT_REQUEST);
        $this->guid = $uuid != null ? $uuid : UuidV4::getFactory()->uuid4()->toString();
        $this->sha256 = $sha256;
        $this->session_id = $SessionId;
    }
}
