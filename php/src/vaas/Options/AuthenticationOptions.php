<?php

namespace VaasSdk\Options;

use InvalidArgumentException;
use VaasSdk\Authentication\GrantType;

class AuthenticationOptions
{
    public function __construct(
        public GrantType $grantType,
        public string $clientId,
        public string $tokenUrl,
        public ?string $clientSecret = null,
        public ?string $userName = null,
        public ?string $password = null
    ) {
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