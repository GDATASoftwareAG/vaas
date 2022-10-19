<?php

namespace VaasSdk\Message;

class VaasVerdict
{
    public function __construct(VerdictResponse $verdictResponse)
    {
        $this->Sha256 = $verdictResponse->sha256 ?? "";
        $this->Verdict = $verdictResponse->verdict ?? Verdict::UNKNOWN;
        $this->Guid = $verdictResponse->guid ?? "";
    }

    public string $Sha256;
    public Verdict $Verdict;
    public string $Guid;
}
