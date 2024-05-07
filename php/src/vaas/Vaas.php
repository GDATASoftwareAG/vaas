<?php

namespace VaasSdk;

use Amp\Future;
use Amp\Http\Client\HttpClient;
use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\HttpException;
use Amp\Http\Client\Request;
use Amp\Http\Client\StreamedContent;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Stream;
use InvalidArgumentException;
use JsonMapper_Exception;
use Ramsey\Uuid\Rfc4122\UuidV4;
use VaasSdk\Exceptions\FileDoesNotExistException;
use VaasSdk\Exceptions\InvalidSha256Exception;
use VaasSdk\Exceptions\TimeoutException;
use VaasSdk\Exceptions\UploadFailedException;
use VaasSdk\Exceptions\VaasClientException;
use VaasSdk\Exceptions\VaasInvalidStateException;
use VaasSdk\Exceptions\VaasServerException;
use VaasSdk\Message\Verdict;
use VaasSdk\Message\VerdictRequest;
use VaasSdk\Message\VerdictRequestForStream;
use VaasSdk\Message\VerdictResponse;
use VaasSdk\Message\VerdictRequestForUrl;
use VaasSdk\VaasOptions;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use VaasSdk\Message\VaasVerdict;
use WebSocket\BadOpcodeException;

class Vaas
{
    private string $_vaasUrl = "wss://gateway.production.vaas.gdatasecurity.de";
    private VaasWebSocket $_vaasWebSocket;
    private int $_uploadTimeoutInSeconds = 600;
    private LoggerInterface $_logger;
    private HttpClient $_httpClient;
    private VaasOptions $_options;

    /**
     */
    public function __construct(?string $vaasUrl, ?LoggerInterface $logger = null, AuthenticatorInterface $authenticator, VaasOptions $options = new VaasOptions())
    {
        $this->_options = $options;
        $this->_httpClient = HttpClientBuilder::buildDefault();
        if ($logger != null)
            $this->_logger = $logger;
        else
            $this->_logger = new NullLogger();
        $this->_logger->debug("Url: " . $vaasUrl);
        if ($vaasUrl)
            $this->_vaasUrl = $vaasUrl;
        $this->_vaasWebSocket = new VaasWebSocket($this->_vaasUrl, $authenticator);
    }

    /**
     */
    public function Connect(
        string          $token,
        ?VaasConnection $vaasConnection = null
    )
    {

    }

    /**
     * Gets verdict for SHA256
     *
     * @param string $hashString the hash to get the verdict for
     * @param string|null $uuid unique identifier
     *
     * @return VaasVerdict the verdict
     * @throws InvalidSha256Exception
     * @throws TimeoutException
     */
    public function ForSha256(string $hashString, string $uuid = null): VaasVerdict
    {
        if ($this->_logger != null)
            $this->_logger->debug("ForSha256WithFlags", ["Sha256" => $hashString]);

        return
            $this->ForSha256Async(
                $hashString,
                $uuid
            )->await();
    }

    /**
     * Gets verdict by url
     *
     * @param string|null $url url to get the verdict for
     * @param string|null $uuid unique identifier
     *
     * @return VaasVerdict the verdict
     *
     * @throws TimeoutException
     * @throws InvalidArgumentException
     */
    public function ForUrl(?string $url, string $uuid = null): VaasVerdict
    {
        if ($this->_logger != null) $this->_logger->debug("ForUrlWithFlags", ["URL:" => $url]);

        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            throw new \InvalidArgumentException("Url is not valid");
        }

        return new VaasVerdict($this->_verdictResponseForUrl(
            $url,
            $uuid
        ));
    }

    /**
     * Gets verdict by file
     *
     * @param string $path the path to get the verdict for
     * @param bool $upload should the file be uploaded if initial verdict is unknown
     * @param string|null $uuid unique identifier
     *
     * @return VaasVerdict the verdict
     * @throws FileDoesNotExistException
     * @throws GuzzleException
     * @throws InvalidSha256Exception
     * @throws UploadFailedException
     */
    public function ForFile(string $path, $upload = true, string $uuid = null): VaasVerdict
    {
        $this->_logger->debug("ForFileWithFlags", ["File" => $path]);

        $sha256 = Sha256::TryFromFile($path);
        $this->_logger->debug("Calculated Hash", ["Sha256" => $sha256]);

        $verdictResponse = $this->ForSha256AsyncInternal(
            $sha256,
            $uuid
        )->await();
        if ($verdictResponse->verdict == Verdict::UNKNOWN && $upload === true) {
            $this->_logger->debug("UploadToken", ["UploadToken" => $verdictResponse->upload_token]);
            $fileStream = fopen($path, 'r');
            $response = $this->_httpClient->put($verdictResponse->url, [
                'body' => $fileStream,
                'timeout' => $this->_uploadTimeoutInSeconds,
                'headers' => ["Authorization" => $verdictResponse->upload_token]
            ]);
            if ($response->getStatusCode() > 399) {
                throw new UploadFailedException($response->getReasonPhrase(), $response->getStatusCode());
            }
            $verdictResponse = $this->_vaasWebSocket->waitForVerdict($verdictResponse->guid)->await();
            return new VaasVerdict($verdictResponse);
        }

        return new VaasVerdict($verdictResponse);
    }

    /**
     * Gets verdict by stream
     *
     * @param Stream $stream
     * @param string|null $uuid unique identifier
     *
     * @return VaasVerdict
     * @throws BadOpcodeException
     * @throws GuzzleException
     * @throws JsonMapper_Exception
     * @throws TimeoutException
     * @throws UploadFailedException
     * @throws VaasClientException
     * @throws VaasInvalidStateException
     * @throws VaasServerException
     */
    public function ForStream(Stream $stream, string $uuid = null): VaasVerdict
    {
        if ($uuid == null) {
            $uuid = UuidV4::getFactory()->uuid4()->toString();
        }

        $verdictResponse = $this->_verdictResponseForStream(
            $uuid
        );

        if ($verdictResponse->verdict != Verdict::UNKNOWN) {
            throw new VaasServerException("Server returned verdict without receiving content.");
        }
        if ($verdictResponse->upload_token == null || $verdictResponse->upload_token == "") {
            throw new JsonMapper_Exception("VerdictResponse missing UploadToken for stream upload.");
        }
        if ($verdictResponse->url == null || $verdictResponse->url == "") {
            throw new JsonMapper_Exception("VerdictResponse missing URL for stream upload.");
        }

        $futureVerdictResponse = $this->_vaasWebSocket->waitForVerdict($verdictResponse->guid);

        $this->UploadStream($stream, $verdictResponse->url, $verdictResponse->upload_token);

        $verdictResponse = $futureVerdictResponse->await();

        return new VaasVerdict($verdictResponse);
    }

    /**
     * @param string $hashString
     * @param string|null $uuid
     * @return Future<VaasVerdict>
     * @throws InvalidSha256Exception
     */
    public function ForSha256Async(string $hashString, string $uuid = null): Future
    {
        return $this->ForSha256AsyncInternal($hashString, $uuid)->map(function ($verdictResponse) {
            return new VaasVerdict($verdictResponse);
        });
    }

    /**
     * @param string $hashString
     * @param string|null $uuid
     * @return Future<VerdictResponse>
     * @throws InvalidSha256Exception
     */
    private function ForSha256AsyncInternal(string $hashString, string $uuid = null): Future
    {
        $sha256 = Sha256::TryFromString($hashString);
        if ($this->_logger != null)
            $this->_logger->debug("_verdictResponseForSha256");

        $request = new VerdictRequest(strtolower($sha256), $uuid);
        $request->use_cache = $this->_options->UseCache;
        $request->use_hash_lookup = $this->_options->UseHashLookup;
        return $this->_vaasWebSocket->sendRequest($request);
    }

    /**
     * @return VerdictResponse
     * @throws TimeoutException
     *
     */
    private function _verdictResponseForUrl(string $url, string $uuid = null): VerdictResponse
    {
        if ($this->_logger != null)
            $this->_logger->debug("_verdictResponseForUrl");

        if (!isset($this->_vaasConnection)) {
            throw new VaasInvalidStateException("connect() was not called");
        }
        $websocket = $this->_vaasConnection->GetAuthenticatedWebsocket();

        $request = new VerdictRequestForUrl($url, $uuid, $this->_vaasConnection->SessionId);
        $request->use_cache = $this->_options->UseCache;
        $request->use_hash_lookup = $this->_options->UseHashLookup;
        $websocket->send(json_encode($request));

        if ($this->_logger != null)
            $this->_logger->debug("verdictResponse", ["VerdictResponse" => json_encode($request)]);

        return $this->_waitForVerdict($request->guid);
    }

    private function _verdictResponseForStream(string $uuid = null): VerdictResponse
    {
        $this->_logger->debug("_verdictResponseForStream");

        $request = new VerdictRequestForStream($uuid);
        $request->use_cache = $this->_options->UseCache;
        $request->use_hash_lookup = $this->_options->UseHashLookup;

        return $this->_vaasWebSocket->sendRequest($request)->await();
    }

    /**
     * Sets the timeout in seconds the websocket client can take for one receive
     *
     * @param int $timeoutInSeconds timeout for the websocket
     *
     * @return void
     */
    public function setWebsocketTimeOut(int $timeoutInSeconds): void
    {
        $this->_vaasConnection->WebSocketClient->setTimeout($timeoutInSeconds);
    }

    /**
     * Sets the timeout in seconds for the loops were we wait for a verdict
     *
     * @param int $timeoutInSeconds timeout for the websocket
     *
     * @return Vaas
     */
    public function setWaitTimeoutInSeconds(int $timeoutInSeconds): self
    {
        $this->_waitTimeoutInSeconds = $timeoutInSeconds;
        return $this;
    }

    /**
     * Set the timeout for the httpclient (for the upload) in seconds
     *
     * @param int $UploadTimeoutInSeconds upload timeout
     *
     * @return Vaas
     */
    public function setUploadTimeout(int $UploadTimeoutInSeconds): self
    {
        $this->_uploadTimeoutInSeconds = $UploadTimeoutInSeconds;
        return $this;
    }

    /**
     * @throws UploadFailedException|HttpException
     */
    private function UploadStream(Stream $stream, string $url, string $uploadToken): void
    {
        $request = new Request($url, "PUT", body: StreamedContent::fromStream($stream));
        $request->addHeader("Authorization", $uploadToken);
        $response = $this->_httpClient->request($request);
        if ($response->getStatus() > 399) {
            throw new UploadFailedException($response->getReason(), $response->getStatus());
        }
    }
}
