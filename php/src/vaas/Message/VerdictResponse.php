<?php

namespace VaasSdk\Message;

class VerdictResponse
{
    public Verdict $verdict;
    public ?string $url;
    public string $guid;
    public string $sha256;
    public ?string $upload_token;
}
