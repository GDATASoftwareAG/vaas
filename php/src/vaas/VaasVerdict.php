<?php

namespace VaasSdk;

class VaasVerdict
{
    public string $sha256;
    public Verdict $verdict;
    public ?string $detection;
    public ?string $fileType;
    public ?string $mimeType;

    public static function from(array $data): self
    {
        $verdict = new self();
        $verdict->sha256 = $data['sha256'];
        $verdict->verdict = Verdict::from($data['verdict']);
        $verdict->detection = $data['detection'] ?? null;
        $verdict->fileType = $data['fileType'] ?? null;
        $verdict->mimeType = $data['mimeType'] ?? null;
        return $verdict;
    }
    
    public function __toString(): string
    {
        return json_encode([
            'sha256' => $this->sha256,
            'verdict' => $this->verdict,
            'detection' => $this->detection,
            'fileType' => $this->fileType,
            'mimeType' => $this->mimeType
        ]);
    }
}