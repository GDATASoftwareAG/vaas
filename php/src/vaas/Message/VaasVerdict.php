<?php

namespace VaasSdk\Message;

class VaasVerdict
{
    public function __construct(VerdictResponse $verdictResponse)
    {
        $this->Sha256 = $verdictResponse->sha256 ?? "";
        $this->Verdict = $verdictResponse->verdict ?? Verdict::UNKNOWN;
        $this->Guid = $verdictResponse->guid ?? "";
        $this->MimeType = $verdictResponse->mime_type ?? null;
        $this->FileType = $verdictResponse->file_type ?? null;
        $this->Detection = $verdictResponse->detection ?? null;
    }

    public string $Sha256;
    public Verdict $Verdict;
    public string $Guid;
    public ?string $FileType;
    public ?string $MimeType;
    public ?string $Detection;
}
