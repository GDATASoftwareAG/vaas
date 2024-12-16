<?php

namespace VaasSdk\Authentication;

use Amp\Cancellation;
use Amp\Future;
use Amp\Http\Client\HttpClient;
use VaasSdk\Options\AuthenticationOptions;
use function Amp\async;

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
    public function __construct(string $clientId, string $clientSecret, ?string $tokenUrl = null, ?HttpClient $httpClient = null)
    {
        $options = new AuthenticationOptions(
            grantType: GrantType::CLIENT_CREDENTIALS,
            clientId: $clientId,
            tokenUrl: $tokenUrl ?? 'https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token',
            clientSecret: $clientSecret
        );
        $this->tokenReceiver = new TokenReceiver($options, $httpClient);
    }

    /**
     * Gets the access token asynchronously.
     * If the token is still valid, it will be returned immediately.
     * If the token is expired, a new token will be requested.
     * @param Cancellation|null $cancellation Cancellation token
     * @return Future Future that resolves to the access token string
     */
    public function getTokenAsync(?Cancellation $cancellation = null): Future
    {
        return async(function () use ($cancellation) {
            return $this->tokenReceiver->getTokenAsync($cancellation)->await();
        });
    }
}