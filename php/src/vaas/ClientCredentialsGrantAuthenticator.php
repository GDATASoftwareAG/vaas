<?php

namespace VaasSdk;

use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\ClientException;
use VaasSdk\Exceptions\VaasAccessDeniedException;

class ClientCredentialsGrantAuthenticator
{
    private string $_clientId;
    private string $_clientSecret;
    private string $_tokenEndpoint;
    private HttpClient $_httpClient;

    public function __construct(string $clientId, $clientSecret, $tokenEndpoint)
    {
        $this->_clientId = $clientId;
        $this->_clientSecret = $clientSecret;
        $this->_tokenEndpoint = $tokenEndpoint;
        $this->_httpClient = new HttpClient();
    }

    public function getToken()
    {
        $headers = ['Content-Type' => 'application/x-www-form-urlencoded'];

        try {
            $response = $this->_httpClient->request(
                'POST',
                $this->_tokenEndpoint,
                [
                    'form_params' => [
                        'client_id' => $this->_clientId,
                        'client_secret' => $this->_clientSecret,
                        'grant_type' => "client_credentials"
                    ],
                    'headers' => $headers
                ]
            );
            if ($response->getStatusCode() != 200) {
                throw new VaasAccessDeniedException($response->getReasonPhrase(), $response->getStatusCode());
            }
        }
        catch (ClientException $e) {
            throw new VaasAccessDeniedException($e->getMessage(), $e->getCode());
        }
        $response_body = json_decode($response->getBody());
        return $response_body->access_token;
    }
}