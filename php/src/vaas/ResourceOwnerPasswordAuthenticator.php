<?php

namespace VaasSdk;

use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use VaasSdk\Exceptions\VaasAuthenticationException;

class ResourceOwnerPasswordAuthenticator {
    private string $clientId;
    private string $userName;
    private string $password;
    private string $tokenEndpoint;
    private $verify;

    public function __construct($clientId, $userName, $password, $tokenEndpoint, $verify=true) {
        $this->clientId = $clientId;
        $this->userName = $userName;
        $this->password = $password;
        $this->tokenEndpoint = $tokenEndpoint;
        $this->verify = $verify;
    }

    /**
     * @throws VaasAuthenticationException
     */
    public function getToken() {
        $provider = new GenericProvider([
            'clientId'                => $this->clientId,
            'urlAuthorize'            => $this->tokenEndpoint,
            'urlAccessToken'          => $this->tokenEndpoint,
            'urlResourceOwnerDetails' => '',
            'verify'                  => $this->verify,
        ]);

        try {
            $accessToken = $provider->getAccessToken("password", [
                'username' => $this->userName,
                'password' => $this->password
            ]);
            return $accessToken->getToken();
        } catch (IdentityProviderException $e) {
            throw new VaasAuthenticationException($e->getMessage(), $e->getCode());
        }
    }
}
