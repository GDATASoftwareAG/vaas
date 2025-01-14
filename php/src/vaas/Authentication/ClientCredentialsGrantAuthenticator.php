<?php

namespace VaasSdk\Authentication;

use Amp\Http\Client\HttpClient;

class ClientCredentialsGrantAuthenticator extends TokenReceiver implements AuthenticatorInterface
{
    private readonly string $clientId;
    private readonly string $clientSecret;
    
    /**
     * The authenticator for the client credentials grant type if you have a client id and client secret.
     * @param string $clientId The client id
     * @param string $clientSecret The client secret
     * @param string|null $tokenUrl The optional token url. Defaults to 'https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token'
     * @param HttpClient|null $httpClient Your optional custom http client.
     */
    public function __construct(string $clientId, string $clientSecret, ?string $tokenUrl = null, ?HttpClient $httpClient = null)
    {
        parent::__construct($tokenUrl, $httpClient);
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
    }

    protected function tokenRequestToForm(): string
    {
        return http_build_query([
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'grant_type' => 'client_credentials',
        ]);
    }
}