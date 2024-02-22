<?php

namespace VaasSdk\Message;

class AuthRequest extends BaseMessage
{
    public string $token;
    public string $session_id;

    public function __construct(string $token, string $sessionId = "")
    {
        parent::__construct(new Kind(Kind::AUTH_REQUEST));
        $this->token = $token;
        $this->session_id = $sessionId;
    }
}
