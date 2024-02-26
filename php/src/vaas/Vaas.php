<?php

namespace VaasSdk;

use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Stream;
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
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use VaasSdk\Message\BaseMessage;
use VaasSdk\Message\BaseVerdictRequest;
use VaasSdk\Message\VaasVerdict;
use WebSocket\BadOpcodeException;

class Vaas
{
    private string $_vaasUrl = "wss://gateway.production.vaas.gdatasecurity.de";
    private VaasConnection $_vaasConnection;
    private int $_waitTimeoutInSeconds = 600;
    private int $_uploadTimeoutInSeconds = 60;
    private LoggerInterface $_logger;
    private HttpClient $_httpClient;

    /**
     */
    public function __construct(?string $vaasUrl, ?LoggerInterface $logger = null)
    {
        $this->_httpClient = new HttpClient();
        if ($logger != null)
            $this->_logger = $logger;
        else
            $this->_logger = new NullLogger();
        $this->_logger->debug("Url: " . $vaasUrl);
        if ($vaasUrl)
            $this->_vaasUrl = $vaasUrl;
    }

    /**
     */
    public function Connect(
        string $token,
        ?VaasConnection $vaasConnection = null
    ) {
        if (isset($vaasConnection)) {
            $this->_vaasConnection = $vaasConnection;
        } else {
            $this->_vaasConnection = new VaasConnection($this->_vaasUrl);
        }
        $webSocket = $this->_vaasConnection->GetConnectedWebsocket();

        $authRequest = new AuthRequest($token);
        $webSocket->send(json_encode($authRequest));
        $authResponse = $this->_waitForAuthResponse();
        if ($this->_logger != null)
            $this->_logger->debug("Authenticated: " . json_encode($authResponse));
        $this->_vaasConnection->SessionId = $authResponse->session_id;
    }

    /**
     * Gets verdict by hashstring
     *
     * @param string $hashString the hash to get the verdict for
     * @param bool   $useCache   enables verdict cache on the server
     * @param bool   $useShed    enables hash-lookup on the server
     * @param string $uuid       unique identifier
     * 
     * @throws Exceptions\InvalidSha256Exception
     * @throws Exceptions\TimeoutException
     * 
     * @return VaasVerdict the verdict
     */
    public function ForSha256WithFlags(string $hashString, bool $useCache = true, bool $useShed = true, string $uuid = null): VaasVerdict
    {
        if ($this->_logger != null)
            $this->_logger->debug("ForSha256WithFlags", ["Sha256" => $hashString]);

        $sha256 = Sha256::TryFromString($hashString);

        return new VaasVerdict($this->_verdictResponseForSha256($sha256, $useCache, $useShed, $uuid));
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
        if ($this->_logger != null)
            $this->_logger->debug("ForSha256", ["Sha256" => $hashString]);

        return $this->ForSha256WithFlags($hashString, true, true, $uuid);
    }

    /**
     * Gets verdict by url
     *
     * @param string|null $url url to get the verdict for
     * @param bool   $useCache   enables verdict cache on the server
     * @param bool   $useShed    enables hash-lookup on the server
     * @param string|null $uuid unique identifier
     *
     * @return VaasVerdict the verdict
     *
     * @throws TimeoutException
     * @throws InvalidArgumentException
     */
    public function ForUrlWithFlags(?string $url, bool $useCache = true, bool $useShed = true, string $uuid = null): VaasVerdict
    {
        if ($this->_logger != null) $this->_logger->debug("ForUrlWithFlags", ["URL:" => $url]);

        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            throw new \InvalidArgumentException("Url is not valid");
        }

        return new VaasVerdict($this->_verdictResponseForUrl($url, $useCache, $useShed, $uuid));
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
        if ($this->_logger != null) $this->_logger->debug("ForUrl", ["URL:" => $url]);

        return $this->ForUrlWithFlags($url, true, true, $uuid);
    }

    /**
     * Gets verdict by file
     *
     * @param string $path   the path to get the verdict for
     * @param bool   $useCache   enables verdict cache on the server
     * @param bool   $useShed    enables hash-lookup on the server
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
    public function ForFileWithFlags(string $path, bool $useCache = true, bool $useShed = true, $upload = true, string $uuid = null): VaasVerdict
    {
        if ($this->_logger != null)
            $this->_logger->debug("ForFileWithFlags", ["File" => $path]);

        $sha256 = Sha256::TryFromFile($path);
        if ($this->_logger != null)
            $this->_logger->debug("Calculated Hash", ["Sha256" => $sha256]);

        $verdictResponse = $this->_verdictResponseForSha256($sha256, $useCache, $useShed, $uuid);
        if ($verdictResponse->verdict == Verdict::UNKNOWN && $upload === true) {
            if ($this->_logger != null)
                $this->_logger->debug("UploadToken", ["UploadToken" => $verdictResponse->upload_token]);
            $fileContent = file_get_contents($path);
            $response = $this->_httpClient->put($verdictResponse->url, [
                'body' => $fileContent,
                'timeout' => $this->_uploadTimeoutInSeconds,
                'headers' => ["Authorization" => $verdictResponse->upload_token]
            ]);
            if ($response->getStatusCode() > 399) {
                throw new UploadFailedException($response->getReasonPhrase(), $response->getStatusCode());
            }
            return new VaasVerdict($this->_waitForVerdict($verdictResponse->guid));
        }

        return new VaasVerdict($verdictResponse);
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
        if ($this->_logger != null)
            $this->_logger->debug("ForFile", ["File" => $path]);

        return $this->ForFileWithFlags($path, true, true, $upload, $uuid);
    }

    /**
     * Gets verdict by stream
     *
     * @param string $path   the path to get the verdict for
     * @param bool   $upload should the file be uploaded if initial verdict is unknown
     * @param string $uuid   unique identifier
     * 

     * @throws JsonMapper_Exception
     * @throws VaasClientException
     * @throws TimeoutException
     * @throws VaasServerException
     * @throws BadOpcodeException
     * @throws VaasInvalidStateException
     * @throws GuzzleException
     * @throws UploadFailedException
     */
    public function ForStreamWithFlags(Stream $stream, bool $useCache = true, bool $useShed = true, string $uuid = null): VaasVerdict
    {
        if ($uuid == null) {
            $uuid = UuidV4::getFactory()->uuid4()->toString();
        }

        $verdictResponse = $this->_verdictResponseForStream($useCache, $useShed, $uuid);

        if ($verdictResponse->verdict != Verdict::UNKNOWN) {
            throw new VaasServerException("Server returned verdict without receiving content.");
        }
        if ($verdictResponse->upload_token == null || $verdictResponse->upload_token == "") {
            throw new JsonMapper_Exception("VerdictResponse missing UploadToken for stream upload.");
        }
        if ($verdictResponse->url == null || $verdictResponse->url == "") {
            throw new JsonMapper_Exception("VerdictResponse missing URL for stream upload.");
        }

        $this->UploadStream($stream, $verdictResponse->url, $verdictResponse->upload_token);

        $verdictResponse = $this->_waitForVerdict($uuid);

        return new VaasVerdict($verdictResponse);
    }

    /**
     * Gets verdict by stream
     *
     * @param string $path   the path to get the verdict for
     * @param bool   $upload should the file be uploaded if initial verdict is unknown
     * @param string $uuid   unique identifier
     * 
     * @throws JsonMapper_Exception
     * @throws VaasClientException
     * @throws TimeoutException
     * @throws VaasServerException
     * @throws BadOpcodeException
     * @throws VaasInvalidStateException
     * @throws GuzzleException
     * @throws UploadFailedException
     */
    public function ForStream(Stream $stream, string $uuid = null): VaasVerdict
    {
        return $this->ForStreamWithFlags($stream, true, true, $uuid);
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
        if ($this->_logger != null)
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
                if ($this->_logger != null)
                    $this->_logger->debug("Result", json_decode($result, true));
                $genericObject = \json_decode($result);
                $resultObject = (new JsonMapper())->map(
                    $genericObject,
                    new BaseMessage()
                );
                if ($resultObject->kind == Kind::AuthResponse) {
                    $authResponse = (new JsonMapper())->map(
                        $genericObject,
                        new AuthResponse()
                    );
                    if ($this->_logger != null)
                        $this->_logger->debug($result);
                    if ($authResponse->success === false) {
                        throw new VaasAuthenticationException($result);
                    }
                    return $authResponse;
                }
                if ($resultObject->kind == Kind::Error) {
                    try {
                        $errorResponse = (new JsonMapper())->map(
                            $genericObject,
                            new Error()
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
        if ($this->_logger != null)
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
                if ($this->_logger != null)
                    $this->_logger->debug("Read timeout, send ping");
                $websocket->ping();
            }
            if ($result != null) {
                if ($this->_logger != null)
                    $this->_logger->debug("Result", json_decode($result, true));
                $resultObject = json_decode($result);
                $baseMessage = (new JsonMapper())->map(
                    $resultObject,
                    new BaseMessage()
                );
                if ($baseMessage->kind == Kind::Error) {
                    try {
                        $errorResponse = (new JsonMapper())->map(
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

                $verdictResponse = (new JsonMapper())->map(
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
            sleep(1);
        }
    }

    /**
     * @throws VaasServerException
     * @throws VaasClientException
     */
    private function _handleWebSocketErrorResponse(Error $errorResponse): void
    {
        if (isset($errorResponse->problem_details->detail)) {
            $details = $errorResponse->problem_details->getDetail();
        } else {
            $details = null;
        }
        $errorType = $errorResponse->getType();
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
    private function _verdictResponseForSha256(Sha256 $sha256, bool $useCache, bool $useShed, string $uuid = null): VerdictResponse
    {
        if ($this->_logger != null)
            $this->_logger->debug("_verdictResponseForSha256");

        if (!isset($this->_vaasConnection)) {
            throw new VaasInvalidStateException("connect() was not called");
        }
        $websocket = $this->_vaasConnection->GetAuthenticatedWebsocket();

        $request = new VerdictRequest(strtolower($sha256), $uuid, $this->_vaasConnection->SessionId);
        $request->UseCache = $useCache;
        $request->UseShed = $useShed;
        $websocket->send(json_encode($request));

        if ($this->_logger != null)
            $this->_logger->debug("verdictResponse", ["VerdictResponse" => json_encode($request)]);

        return $this->_waitForVerdict($request->guid);
    }

    /**
     * @throws TimeoutException
     * 
     * @return VerdictResponse
     */
    private function _verdictResponseForUrl(string $url, bool $useCache, bool $useShed, string $uuid = null): VerdictResponse
    {
        if ($this->_logger != null)
            $this->_logger->debug("_verdictResponseForUrl");

        if (!isset($this->_vaasConnection)) {
            throw new VaasInvalidStateException("connect() was not called");
        }
        $websocket = $this->_vaasConnection->GetAuthenticatedWebsocket();

        $request = new VerdictRequestForUrl($url, $uuid, $this->_vaasConnection->SessionId);
        $request->UseCache = $useCache;
        $request->UseShed = $useShed;
        $websocket->send(json_encode($request));

        if ($this->_logger != null)
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
    private function _verdictResponseForStream(bool $useCache, bool $useShed, string $uuid = null): VerdictResponse
    {
        if ($this->_logger != null)
            $this->_logger->debug("_verdictResponseForStream");

        if (!isset($this->_vaasConnection)) {
            throw new VaasInvalidStateException("connect() was not called");
        }
        $websocket = $this->_vaasConnection->GetAuthenticatedWebsocket();

        $request = new VerdictRequestForStream($this->_vaasConnection->SessionId, $uuid);
        $request->UseCache = $useCache;
        $request->UseShed = $useShed;
        $websocket->send(json_encode($request));

        if ($this->_logger != null)
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
     * @throws GuzzleException
     * @throws UploadFailedException
     */
    private function UploadStream(Stream $stream, string $url, string $uploadToken)
    {
        $response = $this->_httpClient->put($url, [
            'body' => $stream,
            'content-length' => $stream->getSize(),
            'timeout' => $this->_uploadTimeoutInSeconds,
            'headers' => ["Authorization" => $uploadToken]
        ]);
        if ($response->getStatusCode() > 399) {
            throw new UploadFailedException($response->getReasonPhrase(), $response->getStatusCode());
        }
    }
}
