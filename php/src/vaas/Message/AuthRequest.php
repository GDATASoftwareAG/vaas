<?php

namespace VaasSdk\Message;

use Ramsey\Uuid\Rfc4122\UuidV4;

class AuthRequest
{
    public Kind $kind;
    public string $token;
    public string $session_id;

    public function __construct(string $token, string $sessionId = "")
    {
        $this->kind = new Kind(Kind::AUTH_REQUEST);
        $this->token = $token;
        $this->session_id = $sessionId;
    }
}
