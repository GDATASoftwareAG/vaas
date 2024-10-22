<?php

namespace VaasSdk;

use Amp\ByteStream\ReadableStream;
use Amp\DeferredCancellation;
use Amp\Http\Client\HttpClient;
use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\HttpException;
use Amp\Http\Client\Request;
use Amp\Http\Client\StreamedContent;
use Amp\TimeoutCancellation;
use InvalidArgumentException;
use JsonMapper_Exception;
use Ramsey\Uuid\Rfc4122\UuidV4;
use VaasSdk\Exceptions\TimeoutException;
use VaasSdk\Exceptions\UploadFailedException;
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
use Revolt\EventLoop;
use VaasSdk\Authentication\AuthenticatorInterface;
use VaasSdk\Exceptions\VaasClientException;
use VaasSdk\Message\VaasVerdict;
use WebSocket\BadOpcodeException;

class Vaas
{
    private VaasConnection $vaasConnection;
    private int $uploadTimeoutInSeconds = 600;
    private VaasOptions $options;
    private HttpClient $httpClient;
    private ?AuthenticatorInterface $authenticator = null;
    private ?LoggerInterface $logger;
    private ?string $vaasUrl = "wss://gateway.production.vaas.gdatasecurity.de";

    public function __destruct() {
        if (isset($this->vaasConnection)) {
            $this->vaasConnection->close();
        }
    }

    public function withOptions(VaasOptions $options): self
    {
        $this->options = $options;
        return $this;
    }

    public function withHtttpClient(HttpClient $httpClient): self
    {
        $this->httpClient = $httpClient;
        return $this;
    }

    public function withAuthenticator(AuthenticatorInterface $authenticator): self
    {
        $this->authenticator = $authenticator;
        return $this;
    }

    public function withLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;
        return $this;
    }

    public function withUrl(string $vaasUrl): self
    {
        $this->vaasUrl = $vaasUrl;
        return $this;
    }

    public function withVaasConnection(VaasConnection $vaasConnection): self
    {
        $this->vaasConnection = $vaasConnection;
        return $this;
    }

    public function build(): self
    {
        if (!isset($this->logger)) {
            $this->logger = new NullLogger();
        }
        if (!isset($this->vaasConnection) && isset($this->authenticator)) {
            $this->vaasConnection = (new VaasConnection())
                ->withAuthenticator($this->authenticator)
                ->withUrl($this->vaasUrl)
                ->withLogger($this->logger)
                ->build();
        } else if (!isset($this->vaasConnection)) {
            $this->vaasConnection = (new VaasConnection())
                ->withUrl($this->vaasUrl)
                ->withLogger($this->logger)
                ->build();    
        }
        if (!isset($this->options)) {
            $this->options = new VaasOptions();
        }
        if (!isset($this->httpClient)) {
            $this->httpClient = HttpClientBuilder::buildDefault();
        }
        return $this;
    }

    public function Connect(string $token = "") {
        if (!isset($this->vaasConnection)) {
            throw new VaasInvalidStateException("No VaasConnection given and build() was not called");
        }
        $this->vaasConnection->Connect($token);
    }

    /**
     * Gets verdict by hashstring
     *
     * @param string $hashString the hash to get the verdict for
     * @param string $uuid       unique identifier
     * 
     * @throws Exceptions\InvalidSha256Exception
     * @throws Exceptions\TimeoutException
     * 
     * @return VaasVerdict the verdict
     */
    public function ForSha256(string $hashString, string $uuid = null): VaasVerdict {
        $this->logger->debug("ForSha256WithFlags", ["Sha256" => $hashString]);

        $sha256 = Sha256::TryFromString($hashString);

        return new VaasVerdict(
            $this->_verdictResponseForSha256(
                $sha256,
                $uuid
            )
        );
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
        $this->logger->debug("ForUrlWithFlags", ["URL:" => $url]);

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
     * @param string $path   the path to get the verdict for
     * @param bool   $upload should the file be uploaded if initial verdict is unknown
     * @param string $uuid   unique identifier
     * 
     * @throws Exceptions\TimeoutException
     * @throws Exceptions\FileDoesNotExistException
     * @throws Exceptions\InvalidSha256Exception
     * @throws Exceptions\UploadFailedException
     * 
     * @return VaasVerdict the verdict
     */
    public function ForFile(string $path, $upload = true, string $uuid = null): VaasVerdict
    {
        $this->logger->debug("ForFileWithFlags", ["File" => $path]);

        $sha256 = Sha256::TryFromFile($path);
        $this->logger->debug("Calculated Hash", ["Sha256" => $sha256]);

        $verdictResponse = $this->_verdictResponseForSha256(
            $sha256,
            $uuid
        );
        if ($verdictResponse->verdict == Verdict::UNKNOWN && $upload === true) {
            $this->logger->debug("UploadToken", ["UploadToken" => $verdictResponse->upload_token]);

            $fileStream = \Amp\File\openFile($path, 'r');
            $fileSize = \filesize($path);
            
            return new VaasVerdict(
                $this->UploadStream(
                    $fileStream,
                    $verdictResponse->url,
                    $verdictResponse->upload_token,
                    $fileSize,
                    $verdictResponse->guid)
            );
        }

        return new VaasVerdict($verdictResponse);
    }

    /**
     * Gets verdict by stream
     *
     * @param ReadableStream $stream   the path to get the verdict for
     * @param bool   $upload should the file be uploaded if initial verdict is unknown
     * @param string $uuid   unique identifier
     * 
     * @throws JsonMapper_Exception
     * @throws VaasClientException
     * @throws TimeoutException
     * @throws VaasServerException
     * @throws BadOpcodeException
     * @throws VaasInvalidStateException
     * @throws UploadFailedException
     */
    public function ForStream(ReadableStream $stream, int $size = 0, string $uuid = null): VaasVerdict
    {
        $this->logger->debug("uuid: ".var_export($uuid, true));
        $uuid = $uuid ?? UuidV4::getFactory()->uuid4()->toString();
        $this->logger->debug("uuid: ".var_export($uuid, true));
        $verdictResponse = $this->_verdictResponseForStream($uuid);

        if ($verdictResponse->verdict != Verdict::UNKNOWN) {
            throw new VaasServerException("Server returned verdict without receiving content.");
        }
        if ($verdictResponse->upload_token == null || $verdictResponse->upload_token == "") {
            throw new JsonMapper_Exception("VerdictResponse missing UploadToken for stream upload.");
        }
        if ($verdictResponse->url == null || $verdictResponse->url == "") {
            throw new JsonMapper_Exception("VerdictResponse missing URL for stream upload.");
        }

        return new VaasVerdict(
            $this->UploadStream(
                $stream,
                $verdictResponse->url,
                $verdictResponse->upload_token,
                $size,
                $uuid)
        );
    }
  
    /**
     * @throws TimeoutException
     * 
     * @return VerdictResponse
     */
    private function _verdictResponseForSha256(Sha256 $sha256, string $uuid = null): VerdictResponse
    {
        $this->logger->debug("_verdictResponseForSha256");

        if (!isset($this->vaasConnection->SessionId)) {
            throw new VaasInvalidStateException("No Authenticator given and connect() was not called");
        }
        $request = new VerdictRequest(strtolower($sha256), $uuid, $this->vaasConnection->SessionId);
        $request->use_cache = $this->options->UseCache;
        $request->use_hash_lookup = $this->options->UseHashLookup;
        return $this->vaasConnection->SendRequest(json_encode($request), $request->guid)->await();
    }

    /**
     * @throws TimeoutException
     * 
     * @return VerdictResponse
     */
    private function _verdictResponseForUrl(string $url, string $uuid = null): VerdictResponse
    {
        $this->logger->debug("_verdictResponseForUrl");

        if (!isset($this->vaasConnection->SessionId)) {
            throw new VaasInvalidStateException("No Authenticator given and connect() was not called");
        }
        $request = new VerdictRequestForUrl($url, $uuid, $this->vaasConnection->SessionId);
        $request->use_cache = $this->options->UseCache;
        $request->use_hash_lookup = $this->options->UseHashLookup;
        return $this->vaasConnection->SendRequest(json_encode($request), $request->guid)->await();
    }

    /**
     * @throws JsonMapper_Exception
     * @throws VaasClientException
     * @throws TimeoutException
     * @throws VaasServerException
     * @throws BadOpcodeException
     * @throws VaasInvalidStateException
     */
    private function _verdictResponseForStream(string $uuid = null): VerdictResponse
    {
        $this->logger->debug("_verdictResponseForStream");

        if (!isset($this->vaasConnection->SessionId)) {
            throw new VaasInvalidStateException("No Authenticator given and connect() was not called");
        }
        $request = new VerdictRequestForStream($this->vaasConnection->SessionId, $uuid);
        $request->use_cache = $this->options->UseCache;
        $request->use_hash_lookup = $this->options->UseHashLookup;
        return $this->vaasConnection->SendRequest(json_encode($request), $request->guid)->await();
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
        $this->vaasConnection->setTimeout($timeoutInSeconds);
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
        $this->uploadTimeoutInSeconds = $UploadTimeoutInSeconds;
        return $this;
    }

    private function UploadStream(
        ReadableStream $fileStream, 
        string $url, string $uploadToken, int $fileSize,
        string $requestId): VerdictResponse
    {
        $cancellation = new DeferredCancellation();
        $times = 0;
        $pingTimer = EventLoop::repeat(5, function () use(&$times) {
            $this->logger->debug("pinging " . $times++);
            $websocket = $this->vaasConnection->GetAuthenticatedWebsocket();
            $websocket->ping();
        });

        $futureResponse = $this->vaasConnection->GetResponse($requestId);
        try {
            $request = new Request($url, 'PUT');
            $request->setProtocolVersions(["1.1"]);
            $request->setTransferTimeout($this->uploadTimeoutInSeconds);
            $request->setBody(StreamedContent::fromStream($fileStream, $fileSize));
            $request->addHeader("Content-Length", $fileSize);
            $request->addHeader("Authorization", $uploadToken);

            $response = $this->httpClient->request($request, new TimeoutCancellation($this->uploadTimeoutInSeconds));
            if ($response->getStatus() > 399) {
                $reason = $response->getBody()->buffer($cancellation->getCancellation());
                throw new UploadFailedException($reason, $response->getStatus());
            }
        } catch (\Exception $e) {
                if ($e instanceof HttpException) {
                    throw new UploadFailedException($e->getMessage(), $e->getCode());
                }
                throw new VaasClientException($e->getMessage());
        } finally {
            EventLoop::cancel($pingTimer);
            $cancellation->cancel();
            return $futureResponse->getFuture()->await();
        }
    }
}
