<?php

namespace VaasSdk\Authentication;

use Exception;
use React\Http\Browser;
use React\Stream\ReadableStreamInterface;
use VaasSdk\Exceptions\VaasAuthenticationException;

use function React\Async\await;
use function React\Promise\Stream\buffer;

class OAuth2TokenReceiver {
    private string $_tokenEndpoint;
    private string $_clientId;
    private string $_clientSecret;
    private string $_username;
    private string $_password;
    private string $_grantType;
    private Array $_formParams;
    private Browser $_browser;
    private int $_receiveTokenTimeout = 30;

    public function __construct(
        string $tokenEndpoint, string $clientId, string $clientSecret = "",
        string $username = "", string $password = "", Browser $browser = new Browser())
    {
        $this->_browser = $browser;
        $this->_tokenEndpoint = $tokenEndpoint;
        $this->_clientId = $clientId;
        $this->_clientSecret = $clientSecret;
        $this->_username = $username;
        $this->_password = $password;
        $this->_grantType = $this->_clientSecret == "" ? "password" : "client_credentials";

        $this->_formParams = [
            'client_id' => $this->_clientId,
            'grant_type' => $this->_grantType
        ];

        $this->_formParams = match($this->_grantType) {
            "password" => array_merge($this->_formParams, ['username' => $this->_username, 'password' => $this->_password]),
            "client_credentials" => array_merge($this->_formParams, ['client_secret' => $this->_clientSecret]),
            default =>  throw new VaasAuthenticationException("Invalid grant type")
        };
    }

    public function GetToken() {
        $headers = ['Content-Type' => 'application/x-www-form-urlencoded'];

        try {
            $response = await($this->_browser
                ->withTimeout($this->_receiveTokenTimeout)
                ->requestStreaming(
                    'POST',
                    $this->_tokenEndpoint,
                    $headers,
                    \http_build_query($this->_formParams)
                ));
            if ($response->getStatusCode() != 200) {
                throw new VaasAuthenticationException($response->getReasonPhrase(), $response->getStatusCode());
            }
        } catch (Exception $e) {
            throw new VaasAuthenticationException($e->getMessage(), $e->getCode());
        }
        $body = $response->getBody();
        assert($body instanceof ReadableStreamInterface);
        $bodyString = await(buffer($body));
        $response_body = json_decode($bodyString);
        return $response_body->access_token;
    }
}