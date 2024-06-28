<?php

namespace VaasSdk\Message;

class VerdictRequestForStream extends BaseVerdictRequest
{
    public function __construct(string $uuid = null)
    {
        parent::__construct(Kind::VerdictRequestForStream, $uuid);
    }
}
