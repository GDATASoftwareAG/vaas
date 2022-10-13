<?php

namespace VaasSdk\Message;

class AuthResponse
{
    public Kind $kind;
    public bool $success;
    public ?string $session_id;
    public string $text;
}
