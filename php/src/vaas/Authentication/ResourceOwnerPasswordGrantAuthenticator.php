<?php

namespace VaasSdk\Authentication;

use VaasSdk\Authentication\OAuth2TokenReceiver;
use VaasSdk\Exceptions\VaasAuthenticationException;

class ResourceOwnerPasswordGrantAuthenticator implements AuthenticatorInterface {
    private OAuth2TokenReceiver $_tokenReceiver;

    public function __construct($clientId, $userName, $password, $tokenEndpoint) {
        $this->_tokenReceiver = new OAuth2TokenReceiver($tokenEndpoint, $clientId, "", $userName, $password);
    }

    /**
     * @throws VaasAuthenticationException
     */
    public function getToken(): string {
        return $this->_tokenReceiver->GetToken();
    }
}
