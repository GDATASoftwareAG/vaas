<?php

namespace VaasSdk\Message;

class VerdictRequest extends BaseVerdictRequest
{
    public string $sha256;

    public function __construct(string $sha256, string $uuid = null, string $SessionId)
    {
        parent::__construct(Kind::VerdictRequest, $uuid, $SessionId);
        $this->sha256 = $sha256;
    }
}
