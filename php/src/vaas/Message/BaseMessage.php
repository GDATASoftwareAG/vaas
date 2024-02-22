<?php

namespace VaasSdk\Message;

class BaseMessage
{
    public Kind $kind;

    public function __construct(Kind $kind = null)
    {
        $this->kind = $kind;
    }
}
