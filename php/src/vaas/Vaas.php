<?php

namespace VaasSdk;

use Amp\ByteStream\ReadableResourceStream;
use Amp\ByteStream\ReadableStream;
use Amp\DeferredCancellation;
use Amp\Http\Client\HttpClient;
use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\HttpException;
use Amp\Http\Client\Request;
use Amp\Http\Client\StreamedContent;
use Amp\TimeoutCancellation;
use InvalidArgumentException;
use JsonMapper;
use JsonMapper_Exception;
use Ramsey\Uuid\Rfc4122\UuidV4;
use VaasSdk\Exceptions\TimeoutException;
use VaasSdk\Exceptions\UploadFailedException;
use VaasSdk\Exceptions\VaasAuthenticationException;
use VaasSdk\Exceptions\VaasClientException;
use VaasSdk\Exceptions\VaasConnectionClosedException;
use VaasSdk\Exceptions\VaasInvalidStateException;
use VaasSdk\Exceptions\VaasServerException;
use VaasSdk\Message\AuthRequest;
use VaasSdk\Message\AuthResponse;
use VaasSdk\Message\Error;
use VaasSdk\Message\Verdict;
use VaasSdk\Message\Kind;
use VaasSdk\Message\VerdictRequest;
use VaasSdk\Message\VerdictRequestForStream;
use VaasSdk\Message\VerdictResponse;
use VaasSdk\Message\VerdictRequestForUrl;
use VaasSdk\VaasOptions;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Revolt\EventLoop;
use VaasSdk\Message\BaseMessage;
use VaasSdk\Message\VaasVerdict;
use WebSocket\BadOpcodeException;
use WebSocket\Message\Close;
use WebSocket\Message\Ping;

class Vaas
{
    private string $_vaasUrl = "wss://gateway.production.vaas.gdatasecurity.de";
    private VaasConnection $_vaasConnection;
    private int $_waitTimeoutInSeconds = 600;
    private int $_uploadTimeoutInSeconds = 600;
    private LoggerInterface $_logger;
    private VaasOptions $_options;
    private HttpClient $_httpClient;
    private JsonMapper $_jsonMapper;

    /**
     */
    public function __construct(?string $vaasUrl, ?LoggerInterface $logger = new NullLogger(), VaasOptions $options = new VaasOptions())
    {
        $this->_options = $options;
        $this->_httpClient = HttpClientBuilder::buildDefault();
        $this->_logger = $logger;
        $this->_logger->debug("Url: " . $vaasUrl);
        if ($vaasUrl)
            $this->_vaasUrl = $vaasUrl;
        $this->_jsonMapper = new JsonMapper();
        $this->_jsonMapper->bStrictObjectTypeChecking = false;
    }

    /**
     */
    public function Connect(
        string $token,
        ?VaasConnection $vaasConnection = null
    ) {
        $this->_vaasConnection = $vaasConnection ?? new VaasConnection($this->_vaasUrl);
        $webSocket = $this->_vaasConnection->GetConnectedWebsocket();

        $authRequest = new AuthRequest($token);
        $webSocket->send(json_encode($authRequest));
        $authResponse = $this->_waitForAuthResponse();
        $this->_logger->debug("Authenticated: " . json_encode($authResponse));
        $this->_vaasConnection->SessionId = $authResponse->session_id;
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
    public function ForSha256(string $hashString, string $uuid = null): VaasVerdict
    {
        $this->_logger->debug("ForSha256WithFlags", ["Sha256" => $hashString]);

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
        $this->_logger->debug("ForUrlWithFlags", ["URL:" => $url]);

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
        $this->_logger->debug("ForFileWithFlags", ["File" => $path]);

        $sha256 = Sha256::TryFromFile($path);
        $this->_logger->debug("Calculated Hash", ["Sha256" => $sha256]);

        $verdictResponse = $this->_verdictResponseForSha256(
            $sha256,
            $uuid
        );
        if ($verdictResponse->verdict == Verdict::UNKNOWN && $upload === true) {
            $this->_logger->debug("UploadToken", ["UploadToken" => $verdictResponse->upload_token]);

            $fileStream = new ReadableResourceStream(\fopen($path, 'r'));
            $fileSize = \filesize($path);

            $this->UploadStream($fileStream, $verdictResponse->url, $verdictResponse->upload_token, $fileSize);
            
            return new VaasVerdict($this->_waitForVerdict($verdictResponse->guid));
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
        $this->_logger->debug("uuid: ".var_export($uuid, true));
        $uuid = $uuid ?? UuidV4::getFactory()->uuid4()->toString();
        $this->_logger->debug("uuid: ".var_export($uuid, true));
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

        $this->UploadStream($stream, $verdictResponse->url, $verdictResponse->upload_token, $size);

        $verdictResponse = $this->_waitForVerdict($uuid);

        return new VaasVerdict($verdictResponse);
    }

    /**
     * @return AuthResponse
     * @throws VaasConnectionClosedException
     * @throws JsonMapper_Exception
     * @throws TimeoutException
     * @throws VaasAuthenticationException
     * @throws VaasClientException
     * @throws VaasInvalidStateException
     * @throws VaasServerException
     */
    private function _waitForAuthResponse(): AuthResponse
    {
        $websocket = $this->_vaasConnection->GetConnectedWebsocket();
        $this->_logger->debug("WaitForAuthResponse");

        $start_time = time();

        while (true) {
            if ((time() - $start_time) > $this->_waitTimeoutInSeconds) {
                throw new TimeoutException();
            }

            $result = null;
            try {
                $result = $websocket->receive();
            } catch (\WebSocket\TimeoutException $e) {
                $this->_logger->debug("Read timeout, send ping");
                $websocket->ping();
            }

            if ($result != null) {
                if ($result instanceof Ping) {
                    $websocket->pong();
                    continue;
                }
                if ($result instanceof Close) {
                    throw new VaasServerException("Connection closed");
                }
                $result = $result->getContent();
                $this->_logger->debug("Result", json_decode($result, true));
                $genericObject = \json_decode($result);
                $resultObject = $this->_jsonMapper->map(
                    $genericObject,
                    BaseMessage::class
                );
                if ($resultObject->kind == Kind::AuthResponse) {
                    $authResponse = $this->_jsonMapper->map(
                        $genericObject,
                        AuthResponse::class
                    );
                    $this->_logger->debug($result);
                    if ($authResponse->success === false) {
                        throw new VaasAuthenticationException($result);
                    }
                    return $authResponse;
                }
                if ($resultObject->kind == Kind::Error) {
                    try {
                        $errorResponse = $this->_jsonMapper->map(
                            $genericObject,
                            Error::class
                        );
                    } catch (JsonMapper_Exception $e) {
                        // Received error type is not deserializable to Error
                        throw new VaasServerException($e->getMessage());
                    }
                    $this->_handleWebSocketErrorResponse($errorResponse);
                }
            }
            sleep(1);
        }
    }

    /**
     * @param string $guid
     * @return VerdictResponse
     * @throws JsonMapper_Exception
     * @throws TimeoutException
     * @throws VaasClientException
     * @throws VaasInvalidStateException
     * @throws VaasServerException
     */
    private function _waitForVerdict(string $guid): VerdictResponse
    {
        $this->_logger->debug("WaitForVerdict");
        $start_time = time();

        if (!isset($this->_vaasConnection)) {
            throw new VaasInvalidStateException("connect() was not called");
        }
        while (true) {
            $websocket = $this->_vaasConnection->GetAuthenticatedWebsocket();
            if ((time() - $start_time) > $this->_waitTimeoutInSeconds) {
                throw new TimeoutException();
            }
            $result = null;
            try {
                $result = $websocket->receive();
            } catch (\WebSocket\TimeoutException $e) {
                $this->_logger->debug("Read timeout, send ping");
                $websocket->ping();
            }
            if ($result != null) {
                if ($result instanceof Ping) {
                    $websocket->pong();
                    continue;
                }
                if ($result instanceof Close) {
                    throw new VaasServerException("Connection closed");
                }
                $result = $result->getContent();
                $this->_logger->debug("Result", json_decode($result, true));
                $resultObject = json_decode($result);
                $baseMessage = $this->_jsonMapper->map(
                    $resultObject,
                    new BaseMessage()
                );
                if ($baseMessage->kind == Kind::Error) {
                    try {
                        $errorResponse = $this->_jsonMapper->map(
                            $resultObject,
                            new Error()
                        );
                    } catch (JsonMapper_Exception $e) {
                        // Received error type is not deserializable to Error
                        throw new VaasServerException($e->getMessage());
                    }
                    $this->_handleWebSocketErrorResponse($errorResponse);
                }
                if ($baseMessage->kind != Kind::VerdictResponse) {
                    continue;
                }

                $verdictResponse = $this->_jsonMapper->map(
                    $resultObject,
                    new VerdictResponse()
                );
                if (!isset($verdictResponse->guid) || !isset($verdictResponse->kind)) {
                    continue;
                }

                if ($verdictResponse->guid == $guid) {
                    return $verdictResponse;
                }
            }
        }
    }

    /**
     * @throws VaasServerException
     * @throws VaasClientException
     */
    private function _handleWebSocketErrorResponse(Error $errorResponse): void
    {
        if (isset($errorResponse->problem_details->detail)) {
            $details = $errorResponse->problem_details->detail;
        } else {
            $details = null;
        }
        $errorType = $errorResponse->type;
        if ($errorType == "ClientError") {
            throw new VaasClientException($details);
        }
        throw new VaasServerException($details);
    }

    /**
     * @throws TimeoutException
     * 
     * @return VerdictResponse
     */
    private function _verdictResponseForSha256(Sha256 $sha256, string $uuid = null): VerdictResponse
    {
        $this->_logger->debug("_verdictResponseForSha256");

        if (!isset($this->_vaasConnection)) {
            throw new VaasInvalidStateException("connect() was not called");
        }
        $websocket = $this->_vaasConnection->GetAuthenticatedWebsocket();

        $request = new VerdictRequest(strtolower($sha256), $uuid, $this->_vaasConnection->SessionId);
        $request->use_cache = $this->_options->UseCache;
        $request->use_hash_lookup = $this->_options->UseHashLookup;
        $websocket->send(json_encode($request));

        $this->_logger->debug("verdictResponse", ["VerdictResponse" => json_encode($request)]);

        return $this->_waitForVerdict($request->guid);
    }

    /**
     * @throws TimeoutException
     * 
     * @return VerdictResponse
     */
    private function _verdictResponseForUrl(string $url, string $uuid = null): VerdictResponse
    {
        $this->_logger->debug("_verdictResponseForUrl");

        if (!isset($this->_vaasConnection)) {
            throw new VaasInvalidStateException("connect() was not called");
        }
        $websocket = $this->_vaasConnection->GetAuthenticatedWebsocket();

        $request = new VerdictRequestForUrl($url, $uuid, $this->_vaasConnection->SessionId);
        $request->use_cache = $this->_options->UseCache;
        $request->use_hash_lookup = $this->_options->UseHashLookup;
        $websocket->send(json_encode($request));

        $this->_logger->debug("verdictResponse", ["VerdictResponse" => json_encode($request)]);

        return $this->_waitForVerdict($request->guid);
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
        $this->_logger->debug("_verdictResponseForStream");

        if (!isset($this->_vaasConnection)) {
            throw new VaasInvalidStateException("connect() was not called");
        }
        $websocket = $this->_vaasConnection->GetAuthenticatedWebsocket();

        $request = new VerdictRequestForStream($this->_vaasConnection->SessionId, $uuid);
        $request->use_cache = $this->_options->UseCache;
        $request->use_hash_lookup = $this->_options->UseHashLookup;
        $websocket->send(json_encode($request));

        $this->_logger->debug("verdictResponse", ["VerdictResponse" => json_encode($request)]);

        return $this->_waitForVerdict($request->guid);
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
     * Uploads a file stream to a specified URL using a given upload token and file size.
     *
     * @param ReadableStream $fileStream The file stream to upload.
     * @param string $url The URL to upload the file to.
     * @param string $uploadToken The upload token to authenticate the upload.
     * @param int $fileSize The size of the file being uploaded.
     * @throws UploadFailedException If the upload fails.
     * @throws VaasClientException If there is an error with the Vaas client.
     * @return void
     */
    private function UploadStream(ReadableStream $fileStream, string $url, string $uploadToken, int $fileSize): void
    {
        $cancellation = new DeferredCancellation();
        $times = 0;
        $pingTimer = EventLoop::repeat(5, function () use(&$times) {
            $this->_logger->debug("pinging " . $times++);
            $websocket = $this->_vaasConnection->GetAuthenticatedWebsocket();
            $websocket->ping();
        });

        try {
            $request = new Request($url, 'PUT');
            $request->setProtocolVersions(["1.1"]);
            $request->setTransferTimeout($this->_uploadTimeoutInSeconds);
            $request->setBody(StreamedContent::fromStream($fileStream, $fileSize));
            $request->addHeader("Content-Length", $fileSize);
            $request->addHeader("Authorization", $uploadToken);

            $response = $this->_httpClient->request(
                $request, new TimeoutCancellation($this->_uploadTimeoutInSeconds), $cancellation->getCancellation());
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
        }
    }
}
