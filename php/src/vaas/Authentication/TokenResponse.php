<?php

namespace VaasSdk\Authentication;

use InvalidArgumentException;

class TokenResponse
{
    public string $accessToken;
    public ?int $expiresInSeconds;

    public function __construct(string $accessToken, ?int $expiresInSeconds = null)
    {
        if (empty($accessToken)) {
            throw new InvalidArgumentException('Access token cannot be null or empty');
        }
        $this->accessToken = $accessToken;
        $this->expiresInSeconds = $expiresInSeconds;
    }
}