<?php

namespace VaasSdk\Message;

class VerdictRequest extends BaseVerdictRequest
{
    public string $sha256;

    public function __construct(string $sha256, string $uuid = null, string $SessionId)
    {
        parent::__construct(new Kind(Kind::VERDICT_REQUEST), $uuid, $SessionId);
        $this->sha256 = $sha256;
    }
}
