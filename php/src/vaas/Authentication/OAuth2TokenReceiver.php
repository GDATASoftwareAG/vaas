<?php

namespace VaasSdk\Authentication;

use Amp\Http\Client\Form;
use Amp\Http\Client\HttpClient;
use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\Request;
use Amp\TimeoutCancellation;
use Exception;
use VaasSdk\Exceptions\VaasAuthenticationException;

class OAuth2TokenReceiver {
    private string $_tokenEndpoint;
    private string $_clientId;
    private string $_clientSecret;
    private string $_username;
    private string $_password;
    private string $_grantType;
    private Form $_formParams;
    private HttpClient $_browser;
    private int $_receiveTokenTimeout = 30;

    public function __construct(
        string $tokenEndpoint, string $clientId, string $clientSecret = "",
        string $username = "", string $password = "")
    {
        $this->_browser = HttpClientBuilder::buildDefault();
        $this->_tokenEndpoint = $tokenEndpoint;
        $this->_clientId = $clientId;
        $this->_clientSecret = $clientSecret;
        $this->_username = $username;
        $this->_password = $password;
        $this->_grantType = $this->_clientSecret == "" ? "password" : "client_credentials";

        $this->_formParams = new Form();
        $this->_formParams->addField('client_id', $this->_clientId);
        $this->_formParams->addField('grant_type', $this->_grantType);
 
        switch($this->_grantType) {
            case "password":
                $this->_formParams->addField('username', $this->_username);
                $this->_formParams->addField('password', $this->_password);
                break;
            case "client_credentials":
                $this->_formParams->addField('client_secret', $this->_clientSecret);
                break;
            default:
                throw new VaasAuthenticationException("Invalid grant type");
        }
    }

    public function getToken(): string {
        try {
            $request = new Request($this->_tokenEndpoint, 'POST');
            $request->addHeader('Content-Type', 'application/x-www-form-urlencoded');
            $request->setBody($this->_formParams);
            $response = $this->_browser->request($request, new TimeoutCancellation($this->_receiveTokenTimeout));
            if ($response->getStatus() != 200) {
                throw new VaasAuthenticationException($response->getReason(), $response->getStatus());
            }
        } catch (Exception $e) {
            throw new VaasAuthenticationException($e->getMessage(), $e->getCode());
        }
        $body = $response->getBody()->buffer();
        $response_body = json_decode($body);
        return $response_body->access_token;
    }
}