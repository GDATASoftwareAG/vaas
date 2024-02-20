<?php

namespace VaasSdk\Message;

use Ramsey\Uuid\Rfc4122\UuidV4;

class VerdictRequestForStream
{
    public string $guid;
    public Kind $kind;
    public string $session_id;

    public function __construct(string $SessionId, string $uuid = null)
    {
        $this->kind = new Kind(Kind::VERDICT_REQUEST_FOR_URL);
        $this->guid = $uuid != null ? $uuid : UuidV4::getFactory()->uuid4()->toString();
        $this->session_id = $SessionId;
    }
}
