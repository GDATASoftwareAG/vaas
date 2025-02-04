<?php

namespace VaasSdk\Authentication;

use Amp\Http\Client\HttpClient;

class ResourceOwnerPasswordGrantAuthenticator extends TokenReceiver implements AuthenticatorInterface
{
    private readonly string $clientId;
    private readonly string $userName;
    private readonly string $password;

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
        parent::__construct($tokenUrl, $httpClient);
        $this->clientId = $clientId;
        $this->userName = $userName;
        $this->password = $password;
    }

    protected function tokenRequestToForm(): string
    {
        return http_build_query([
            'client_id' => $this->clientId,
            'username' => $this->userName,
            'password' => $this->password,
            'grant_type' => 'password',
        ]);
    }
}
