<?php

namespace VaasSdk;

use Amp\Http\Client\HttpClient;
use Amp\Http\Client\HttpClientBuilder;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use VaasSdk\Authentication\AuthenticatorInterface;
use VaasSdk\Exceptions\VaasClientException;
use VaasSdk\Options\VaasOptions;

class VaasBuilder
{
    private HttpClient $httpClient;
    private AuthenticatorInterface $authenticator;
    private VaasOptions $options;
    private LoggerInterface $logger;

    /**
     * Optional parameters for the Vaas client like
     * - the URL of the VaaS backend
     * - whether to use the cache (default: true)
     * - whether to use the G DATA cloud for hash lookups (default: true)
     * - the timeout in seconds for the file upload to the VaaS backend (default: 300)
     * @param VaasOptions $options Options for the Vaas client
     * @return $this
     */
    public function withOptions(VaasOptions $options): self
    {
        $this->options = $options;
        return $this;
    }

    /**
     * @param HttpClient $httpClient Your optional custom http client.
     * @return $this
     */
    public function withHttpClient(HttpClient $httpClient): self
    {
        $this->httpClient = $httpClient;
        return $this;
    }

    /**
     * Either use the `ClientCredentialsGrantAuthenticator` or `ResourceOwnerPasswordGrantAuthenticator`
     * Use the `ClientCredentialsGrantAuthenticator` if you have a client id and client secret.
     * Use the `ResourceOwnerPasswordGrantAuthenticator` if you have a username and password.
     * Last one is the choice if you have registered yourself on https://vaas.gdata.de/login. In this case, the client id is `vaas-customer`.
     * @param AuthenticatorInterface $authenticator The authenticator to use
     * @return $this
     */
    public function withAuthenticator(AuthenticatorInterface $authenticator): self
    {
        $this->authenticator = $authenticator;
        return $this;
    }

    /**
     * Set the logger to use
     * @param LoggerInterface $logger The logger to use
     * @return $this
     */
    public function withLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;
        return $this;
    }

    /**
     * Build the Vaas client
     * @return Vaas The Vaas client
     * @throws VaasClientException If the authenticator is not set
     */
    public function build(): Vaas
    {
        if (!isset($this->logger)) {
            $this->logger = new NullLogger();
        }
        if (!isset($this->authenticator)) {
            throw new VaasClientException('Authenticator is required');
        }
        if (!isset($this->httpClient)) {
            $this->httpClient = HttpClientBuilder::buildDefault();
        }
        if (!isset($this->options)) {
            $this->options = new VaasOptions();
        }

        $vaas = Vaas::createInstance();
        $vaas->withHttpClient($this->httpClient);
        $vaas->withAuthenticator($this->authenticator);
        $vaas->withOptions($this->options);
        $vaas->withLogger($this->logger);
        return $vaas;
    }
}