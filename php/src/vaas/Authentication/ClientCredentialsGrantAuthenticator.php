<?php

namespace VaasSdk\Authentication;

class ClientCredentialsGrantAuthenticator
{
    private OAuth2TokenReceiver $_tokenReceiver;
    public function __construct(
        string $clientId,
        string $clientSecret,
        string $tokenEndpoint = "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"
    ) {
        $this->_tokenReceiver = new OAuth2TokenReceiver($tokenEndpoint, $clientId, $clientSecret);
    }

    public function getToken(): string
    {
        return $this->_tokenReceiver->GetToken();
    }
}
