<?php

namespace VaasSdk\Authentication;

class ClientCredentialsTokenReceiver extends TokenReceiver
{
    protected function tokenRequestToForm(): string
    {
        return http_build_query([
            'client_id' => $this->authenticator->clientId,
            'client_secret' => $this->authenticator->clientSecret,
            'grant_type' => 'client_credentials',
        ]);
    }
}