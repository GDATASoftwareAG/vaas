<?php

namespace VaasSdk\Authentication;

class ResourceOwnerPasswordTokenReceiver extends TokenReceiver
{
    protected function tokenRequestToForm(): string
    {
        return http_build_query([
            'client_id' => $this->authenticator->clientId,
            'username' => $this->authenticator->userName,
            'password' => $this->authenticator->password,
            'grant_type' => 'password',
        ]);
    }
}