<?php

namespace VaasSdk\Message;

class Error extends BaseMessage
{
    public string $type;
    public string $requestId;
    public string $text;
    public ?ProblemDetails $problem_details;

    public function __construct()
    {
        $this->kind = Kind::Error;
    }
}
