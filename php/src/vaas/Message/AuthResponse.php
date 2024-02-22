<?php

namespace VaasSdk\Message;

class AuthResponse extends BaseMessage
{
    public bool $success;
    public ?string $session_id;
    public string $text;

    public function __construct()
    {
        parent::__construct(new Kind(Kind::AUTH_RESPONSE));
    }
}
