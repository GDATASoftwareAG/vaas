<?php

namespace VaasSdk\Authentication;

use Amp\Cancellation;
use Amp\Http\Client\HttpClient;

class ClientCredentialsGrantAuthenticator implements AuthenticatorInterface
{
    private TokenReceiver $tokenReceiver;

    /**
     * The authenticator for the client credentials grant type if you have a client id and client secret.
     * @param string $clientId The client id
     * @param string $clientSecret The client secret
     * @param string|null $tokenUrl The optional token url. Defaults to 'https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token'
     * @param HttpClient|null $httpClient Your optional custom http client.
     */
    public function __construct(public string $clientId, public string $clientSecret, ?string $tokenUrl = null, ?HttpClient $httpClient = null)
    {
        $this->tokenReceiver = new TokenReceiver($this, $tokenUrl, $httpClient);
    }

    /**
     * Gets the access token asynchronously.
     * If the token is still valid, it will be returned immediately.
     * If the token is expired, a new token will be requested.
     * @param Cancellation|null $cancellation Cancellation token
     * @return string The access token string
     */
    public function getTokenAsync(?Cancellation $cancellation = null): string
    {
        return $this->tokenReceiver->getTokenAsync($cancellation)->await();
    }
}