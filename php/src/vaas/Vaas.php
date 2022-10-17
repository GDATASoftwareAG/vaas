<?php

namespace VaasSdk;

use Exception;
use GuzzleHttp\Client as HttpClient;
use JsonMapper;
use Monolog\Formatter\JsonFormatter;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;
use VaasSdk\Exceptions\TimeoutException;
use VaasSdk\Exceptions\UploadFailedException;
use VaasSdk\Exceptions\VaasAuthenticationException;
use VaasSdk\Exceptions\VaasInvalidStateException;
use VaasSdk\Message\AuthRequest;
use VaasSdk\Message\AuthResponse;
use VaasSdk\Message\Verdict;
use VaasSdk\Message\Kind;
use VaasSdk\Message\VerdictRequest;
use VaasSdk\Message\VerdictResponse;
use Psr\Log\LoggerInterface;

class Vaas
{
    private string $_vaasUrl = "wss://gateway-vaas.gdatasecurity.de";
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
        if ($logger == null) {
            $monoLogger = new Logger("VaaS");

            $streamHandler = new StreamHandler(
                fopen('php://stdout', 'w'),
                Logger::INFO
            );
            $streamHandler->setFormatter(new JsonFormatter());
            $monoLogger->pushHandler($streamHandler);
            $this->_logger = $monoLogger;
        } else {
            $this->_logger = $logger;
        }
    }

    /**
     */
    public function Connect(
        string $token,
        ?LoggerInterface $logger = null,
        ?VaasConnection $vaasConnection = null
    ) {
        if (isset($vaasConnection)) {
            $this->_vaasConnection = $vaasConnection;
        } else {
            $this->_vaasConnection = new VaasConnection($this->_vaasUrl);
        }
        $webSocket = $this->_vaasConnection->GetConnectedWebsocket();

        if ($logger == null) {
            $monoLogger = new Logger("VaaS");

            $streamHandler = new StreamHandler(
                fopen('php://stdout', 'w'),
                Logger::INFO
            );
            $streamHandler->setFormatter(new JsonFormatter());
            $monoLogger->pushHandler($streamHandler);
            $this->_logger = $monoLogger;
        } else {
            $this->_logger = $logger;
        }
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
     * @return string the verdict
     */
    public function ForSha256(string $hashString, string $uuid = null): string
    {
        $this->_logger->debug("ForSha256", ["Sha256" => $hashString]);

        $verdictResponse = $this->VerdictResponseForSha256($hashString, $uuid);
        return $verdictResponse->verdict;
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
     * @return VerdictResponse the verdict
     */
    public function VerdictResponseForSha256(string $hashString, string $uuid = null): VerdictResponse
    {
        $this->_logger->debug("VerdictResponseForSha256", ["Sha256" => $hashString]);

        $sha256 = Sha256::TryFromString($hashString);

        return $this->_verdictResponseForSha256($sha256, $uuid);
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
     * @return string the verdict
     */
    public function ForFile(string $path, bool $upload = true, string $uuid = null): string
    {
        $this->_logger->debug("ForFile", ["File" => $path]);

        $verdictResponse = $this->VerdictResponseForFile($path, $upload, $uuid);

        return $verdictResponse->verdict;
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
     * @return VerdictResponse the verdict
     */
    public function VerdictResponseForFile(string $path, bool $upload = true, string $uuid = null): VerdictResponse
    {
        $this->_logger->debug("VerdictResponseForFile", ["File" => $path]);

        $sha256 = Sha256::TryFromFile($path);
        $this->_logger->debug("Calculated Hash", ["Sha256" => $sha256]);

        $verdictResponse = $this->_verdictResponseForSha256($sha256, $uuid);
        if ($verdictResponse->verdict == Verdict::UNKNOWN && $upload === true) {
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
            return $this->_waitForVerdict($verdictResponse->guid);
        }

        return $verdictResponse;
    }


    /**
     * @throws TimeoutException
     * 
     * @return AuthResponse
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
            try {
                $result = null;
                try {
                    $result = $websocket->receive();
                } catch (\WebSocket\TimeoutException $e) {
                    $this->_logger->debug("Read timeout, send ping");
                    $websocket->ping();
                }

                if ($result != null) {
                    $this->_logger->debug("Result", json_decode($result, true));

                    $resultObject = json_decode($result);
                    if ($resultObject->kind == Kind::AUTH_RESPONSE) {
                        $authResponse = (new JsonMapper())->map(
                            $resultObject,
                            new AuthResponse()
                        );
                        $this->_logger->debug($result);
                        if ($authResponse->success === false) {
                            throw new VaasAuthenticationException($result);
                        }
                        return $authResponse;
                    }
                }
            } catch (VaasAuthenticationException $e) {
                throw $e;
            } catch (Exception $e) {
                $this->_logger->warning("Error", ["Error" => $e]);
            }
            sleep(1);
        }
    }

    /**
     * @throws TimeoutException
     * 
     * @return VerdictResponse
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
            try {
                $result = null;
                try {
                    $result = $websocket->receive();
                } catch (\WebSocket\TimeoutException $e) {
                    $this->_logger->debug("Read timeout, send ping");
                    $websocket->ping();
                }
                if ($result != null) {
                    $this->_logger->debug("Result", json_decode($result, true));
                    $resultObject = json_decode($result);
                    if (!isset($resultObject->guid) || !isset($resultObject->kind)) {
                        continue;
                    }
                    if ($resultObject->kind != Kind::VERDICT_RESPONSE) {
                        continue;
                    }
                    if ($resultObject->guid == $guid) {
                        $result = (new JsonMapper())->map(
                            $resultObject,
                            new VerdictResponse()
                        );
                        return $result;
                    }
                }
            } catch (Exception $e) {
                $this->_logger->warning("Error", ["Error" => $e]);
            }
            sleep(1);
        }
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
}
