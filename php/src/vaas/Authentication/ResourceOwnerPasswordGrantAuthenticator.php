<?php

namespace VaasSdk\Authentication;

use Amp\Cancellation;
use Amp\Http\Client\HttpClient;
use VaasSdk\Options\AuthenticationOptions;

class ResourceOwnerPasswordGrantAuthenticator implements AuthenticatorInterface
{
    private TokenReceiver $tokenReceiver;

    /**
     * The authenticator for the resource owner password grant type if you have a client id, username and password.
     * This is the choice if you have registered yourself on https://vaas.gdata.de/login. In this case, the client id is `vaas-customer`.
     * @param string $clientId The client id
     * @param string $userName Your username or email
     * @param string $password Your password
     * @param string|null $tokenUrl The optional token url. Defaults to 'https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token'
     * @param HttpClient|null $httpClient Your optional custom http client.
     */
    public function __construct(string $clientId, string $userName, string $password, ?string $tokenUrl = null, ?HttpClient $httpClient = null)
    {
        $options = new AuthenticationOptions(
            grantType: GrantType::PASSWORD,
            clientId: $clientId,
            tokenUrl: $tokenUrl ?? 'https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token',
            userName: $userName,
            password: $password
        );
        $this->tokenReceiver = new TokenReceiver($options, $httpClient);
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