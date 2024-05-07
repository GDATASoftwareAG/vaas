<?php

namespace VaasSdk\Message;

class VerdictRequestForUrl extends BaseVerdictRequest
{
    public string $url;

    public function __construct(string $url, string $uuid = null)
    {
        parent::__construct(Kind::VerdictRequestForUrl, $uuid);
        $this->url = $url;
    }
}
