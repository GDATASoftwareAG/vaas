<?php

namespace VaasSdk\Options;

use InvalidArgumentException;
use VaasSdk\Authentication\GrantType;

class AuthenticationOptions
{
    public string $grantType;
    public string $clientId;
    public ?string $clientSecret;
    public ?string $userName;
    public ?string $password;

    public function __construct(
        string $grantType,
        string $clientId,
        ?string $clientSecret = null,
        ?string $userName = null,
        ?string $password = null
    ) {
        $this->grantType = $grantType;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->userName = $userName;
        $this->password = $password;

        $this->validate();
    }

    private function validate(): void
    {
        if ($this->grantType === GrantType::CLIENT_CREDENTIALS) {
            if (empty($this->clientId) || empty($this->clientSecret)) {
                throw new InvalidArgumentException(
                    'The fields clientId and clientSecret are required for the grantType \'Client Credentials\'.'
                );
            }
        } elseif ($this->grantType === GrantType::PASSWORD) {
            if (empty($this->clientId) || empty($this->userName) || empty($this->password)) {
                throw new InvalidArgumentException(
                    'The fields clientId, userName and password are required for the grantType \'Password\'.'
                );
            }
        } else {
            throw new InvalidArgumentException('Invalid grantType provided.');
        }
    }
}