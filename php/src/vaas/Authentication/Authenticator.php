<?php

namespace VaasSdk\Authentication;

use Amp\Cancellation;
use Amp\Future;
use Amp\Http\Client\HttpClient;
use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\Request;
use Amp\Sync\LocalMutex;
use Amp\Sync\Mutex;
use Exception;
use InvalidArgumentException;
use VaasSdk\Exceptions\VaasAuthenticationException;
use VaasSdk\Options\AuthenticationOptions;
use VaasSdk\Options\VaasOptions;
use function Amp\async;
use function Amp\delay;

class Authenticator
{
    private HttpClient $httpClient;
    private VaasOptions $options;
    private AuthenticationOptions $credentials;
    private Mutex $mutex;
    private ?TokenResponse $lastTokenResponse = null;
    private int $validTo = 0;
    private ?int $lastRequestTime = null;

    public function __construct(AuthenticationOptions $credentials, ?VaasOptions $options = null, ?HttpClient $httpClient = null)
    {
        $this->credentials = $credentials;
        $this->options = $options ?? new VaasOptions();
        $this->httpClient = $httpClient ?? HttpClientBuilder::buildDefault();
        $this->mutex = new LocalMutex();
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
            $lock = $this->mutex->acquire();
            try {
                $now = time();
                if ($this->lastTokenResponse !== null && $this->validTo > $now) {
                    return $this->lastTokenResponse->accessToken;
                }

                if ($this->lastRequestTime !== null) {
                    $timeToWait = $this->lastRequestTime + 1 - $now;
                    if ($timeToWait > 0) {
                        delay($timeToWait);
                    }
                }

                $this->lastRequestTime = time();
                $this->lastTokenResponse = $this->requestTokenAsync($cancellation)->await();
                $expiresInSeconds = $this->lastTokenResponse->expiresInSeconds ?? throw new VaasAuthenticationException("Identity provider did not return expires_in");

                $this->validTo = time() + $expiresInSeconds;
                return $this->lastTokenResponse->accessToken;
            }
            catch (Exception $ex) {
                throw new VaasAuthenticationException("Failed to get token", $ex->getCode(), $ex);
            }
            finally {
                $lock->release();
            }
        });
    }

    /**
     * Requests a new token asynchronously.
     * @param Cancellation|null $cancellation Cancellation token
     * @return Future Future that resolves to a TokenResponse
     */
    private function requestTokenAsync(?Cancellation $cancellation = null): Future
    {
        return async(function () use ($cancellation) {
            $form = $this->tokenRequestToForm();
            $request = new Request($this->options->tokenUrl, 'POST');
            $request->setBody($form);
            $request->setHeader('Content-Type', 'application/x-www-form-urlencoded');

            try {
                $response = $this->httpClient->request($request, $cancellation);
            } catch (Exception $ex) {
                throw new VaasAuthenticationException("Failed to request token", $ex->getCode(), $ex);
            }

            $stringResponse = $response->getBody()->buffer($cancellation);

            if (!$response->isSuccessful()) {
                $statusCode = $response->getStatus();
                $errorResponse = json_decode($stringResponse, true);
                if ($errorResponse === null) {
                    throw new VaasAuthenticationException("Identity provider returned status code $statusCode: Empty body");
                }

                throw new VaasAuthenticationException("Identity provider returned status code $statusCode: " . ($errorResponse['error_description'] ?? $errorResponse['error']));
            }

            $tokenResponse = json_decode($stringResponse, true);
            if ($tokenResponse === null) { throw new VaasAuthenticationException("Identity provider returned invalid JSON"); }
            if ($tokenResponse['access_token'] === null) { throw new VaasAuthenticationException("Access token is null"); }
            if ($tokenResponse['expires_in'] === null) { throw new VaasAuthenticationException("expires_in is null"); }

            return new TokenResponse($tokenResponse['access_token'], $tokenResponse['expires_in']);
        });
    }

    /**
     * Converts the token request to form data.
     * @return string Form data for the token request
     */
    private function tokenRequestToForm(): string
    {
        if ($this->credentials->grantType === GrantType::CLIENT_CREDENTIALS) {
            return http_build_query([
                'client_id' => $this->credentials->clientId,
                'client_secret' => $this->credentials->clientSecret ?? throw new InvalidArgumentException(),
                'grant_type' => 'client_credentials',
            ]);
        }

        return http_build_query([
            'client_id' => $this->credentials->clientId,
            'username' => $this->credentials->userName ?? throw new InvalidArgumentException(),
            'password' => $this->credentials->password ?? throw new InvalidArgumentException(),
            'grant_type' => 'password',
        ]);
    }
}