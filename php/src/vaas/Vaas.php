<?php

namespace VaasSdk;

use Exception;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\GuzzleException;
use JsonMapper;
use Monolog\Formatter\JsonFormatter;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;
use VaasSdk\Exceptions\TimeoutException;
use VaasSdk\Exceptions\UploadFailedException;
use VaasSdk\Exceptions\AccessDeniedException;
use VaasSdk\Message\AuthRequest;
use VaasSdk\Message\AuthResponse;
use VaasSdk\Message\Verdict;
use VaasSdk\Message\Kind;
use VaasSdk\Message\VerdictRequest;
use VaasSdk\Message\VerdictResponse;
use WebSocket\BadOpcodeException;
use WebSocket\Client as WebSocketClient;
use Psr\Log\LoggerInterface;

class Vaas
{
    private string $VaasUrl = "wss://gateway-vaas.gdatasecurity.de";
    private string $token;
    private string $sessionId;
    private WebSocketClient $webSocketClient;
    private HttpClient $HttpClient;
    private int $waitTimeoutInSeconds = 600;
    private int $uploadTimeoutInSeconds = 60;
    private LoggerInterface $logger;

    /**
     * @throws BadOpcodeException|TimeoutException
     */
    public function __construct(
        string $token,
        ?LoggerInterface $logger = null
    ) {        
        $this->token = $token;
        $this->webSocketClient = new WebSocketClient($this->VaasUrl);
        $this->webSocketClient->ping();

        $this->HttpClient = new HttpClient();

        if ($logger == null) {
            $monoLogger = new Logger("VaaS");
            
            $streamHandler = new StreamHandler(
                STDOUT, 
                Logger::INFO
            );
            $streamHandler->setFormatter(new JsonFormatter());
            $monoLogger->pushHandler($streamHandler);
            $this->logger = $monoLogger;
        }
        else {
            $this->logger = $logger;
        }
        $authRequest = new AuthRequest($this->token);
        $this->webSocketClient->send(json_encode($authRequest));
        $authResponse = $this->WaitForAuthResponse();
        $this->logger->debug("Authenticated: ".json_encode($authResponse));
        
        $this->sessionId = $authResponse->session_id;
    }

    /**
     * Gets verdict by hashstring
     *
     * @param string $hashString the hash to get the verdict for
     * @throws Exceptions\InvalidSha256Exception
     * @throws Exceptions\TimeoutException
     * @throws BadOpcodeException
     */
    public function ForSha256(string $hashString, string $uuid = null): string
    {

        $this->logger->debug("ForSha256", ["Sha256"=>$hashString]);

        $sha256 = Sha256::TryFromString($hashString);

        $verdictResponse = $this->VerdictResponseForSha256($sha256, $uuid);
        return $verdictResponse->verdict;
    }

    /**
     * Gets verdict by file
     *
     * @param string $path the path to get the verdict for
     * @param bool $upload should the file be uploaded if initial verdict is unknown
     * @throws GuzzleException
     * @throws Exceptions\TimeoutException
     * @throws Exceptions\FileDoesNotExistException
     * @throws Exceptions\InvalidSha256Exception
     * @throws Exceptions\UploadFailedException
     * @throws BadOpcodeException
     */
    public function ForFile(string $path, bool $upload = true, string $uuid = null): string
    {
        $this->logger->debug("ForFile", ["File"=>$path]);

        $sha256 = Sha256::TryFromFile($path);
        $this->logger->debug("Calculated Hash", ["Sha256"=>$sha256]);

        $verdictResponse = $this->VerdictResponseForSha256($sha256, $uuid);
        if ($verdictResponse->verdict == Verdict::UNKNOWN && $upload === true) {
            $this->logger->debug("UploadToken", ["UploadToken"=>$verdictResponse->upload_token]);
            $fileContent = file_get_contents($path);
            $response = $this->HttpClient->put($verdictResponse->url, [
                'body' => $fileContent,
                'timeout' => $this->uploadTimeoutInSeconds,
                'headers' =>["Authorization" => $verdictResponse->upload_token] 
            ]);
            if ($response->getStatusCode() > 399) {
                throw new UploadFailedException();
            }
            $verdictResponse = $this->WaitForVerdict($verdictResponse->guid);
            return $verdictResponse->verdict;
        }

        return $verdictResponse->verdict;
    }

    /**
     * @throws TimeoutException
     */
    private function WaitForAuthResponse(): AuthResponse
    {
        $this->logger->debug("WaitForAuthResponse");
        
        $start_time = time();

        while (true) {
            if ((time() - $start_time) > $this->waitTimeoutInSeconds) {
                throw new TimeoutException();
            }
            try {
                $result = null;
                try {
                    $result = $this->webSocketClient->receive();
                } catch(\WebSocket\TimeoutException $e) {
                    $this->logger->debug("Read timeout, send ping");
                    $this->webSocketClient->ping();
                }

                if ($result != null) {
                    $this->logger->debug("Result", json_decode($result, true));

                    $resultObject = json_decode($result);
                    if ($resultObject->kind == Kind::AUTH_RESPONSE) {
                        $authResponse =  (new JsonMapper())->map(
                            $resultObject,
                            new AuthResponse()
                        );
                        if ($authResponse->success === false) {
                            throw new AccessDeniedException();
                        } 
                        return $authResponse;
                    }
                }
            } catch (Exception $e) {
                $this->logger->warning("Error", ["Error"=>$e]);
            }
            sleep(1);
        }
    }

    /**
     * @throws TimeoutException
     */
    private function WaitForVerdict(string $guid): VerdictResponse
    {
        $this->logger->debug("WaitForVerdict");
        if ($this->webSocketClient->isConnected() === false) {
            $this->logger->debug("disconnected");
        }
        $start_time = time();

        while (true) {
            if ((time() - $start_time) > $this->waitTimeoutInSeconds) {
                throw new TimeoutException();
            }
            try {
                $result = null;
                try {
                    $result = $this->webSocketClient->receive();
                } catch(\WebSocket\TimeoutException $e) {
                    $this->logger->debug("Read timeout, send ping");
                    $this->webSocketClient->ping();
                }
                if ($result != null) {
                    $this->logger->debug("Result", json_decode($result, true));
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
            }
            catch (Exception $e) {
                $this->logger->warning("Error", ["Error"=>$e]);
            }
            sleep(1);
        }
    }


    /**
     * @throws TimeoutException
     * @throws BadOpcodeException
     */
    private function VerdictResponseForSha256(Sha256 $sha256, string $uuid = null): VerdictResponse
    {
        $this->logger->debug("VerdictResponseForSha256");

        $request = new VerdictRequest(strtolower($sha256), $uuid, $this->sessionId);
        $this->webSocketClient->send(json_encode($request));

        return $this->WaitForVerdict($request->guid);
    }

    /**
     * Sets the timeout in seconds the websocket client can take for one receive
     *
     * @param int $timeoutInSeconds
     */
    public function setWebsocketTimeOut(int $timeoutInSeconds): void
    {
        $this->webSocketClient->setTimeout($timeoutInSeconds);
    }

    /**
     * Sets the timeout in seconds for the loops were we wait for a verdict
     *
     */
    public function setWaitTimeoutInSeconds(int $timeoutInSeconds): self
    {
        $this->waitTimeoutInSeconds = $timeoutInSeconds;
        return $this;
    }

    /**
     * Set the timeout for the httpclient (for the upload) in seconds
     *
     * @param int $UploadTimeoutInSeconds
     * @return Vaas
     */
    public function setUploadTimeout(int $UploadTimeoutInSeconds): self
    {
        $this->uploadTimeoutInSeconds = $UploadTimeoutInSeconds;
        return $this;
    }
}
