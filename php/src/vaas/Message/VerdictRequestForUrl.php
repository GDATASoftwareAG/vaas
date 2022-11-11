<?php

namespace VaasSdk\Message;

use Ramsey\Uuid\Rfc4122\UuidV4;

class VerdictRequestForUrl
{
    public string $url;
    public string $guid;
    public Kind $kind;
    public string $session_id;

    public function __construct(string $url, string $uuid = null, string $SessionId)
    {
        $this->kind = new Kind(Kind::VERDICT_REQUEST_FOR_URL);
        $this->guid = $uuid != null ? $uuid : UuidV4::getFactory()->uuid4()->toString();
        $this->url = $url;
        $this->session_id = $SessionId;
    }
}
