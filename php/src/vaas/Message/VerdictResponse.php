<?php

namespace VaasSdk\Message;

class VerdictResponse extends BaseMessage
{
    public Verdict $verdict;
    public ?string $url;
    public string $guid;
    public string $sha256;
    public ?string $upload_token;
    public ?string $file_type;
    public ?string $mime_type;
    public ?string $detection;
}
