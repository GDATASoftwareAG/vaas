<?php

namespace VaasSdk;

use Amp\Cache\Cache;
use Amp\Future;
use Amp\Websocket\WebsocketClient;
use Psr\Log\LoggerInterface;
use VaasSdk\Authentication\AuthenticatorInterface;
use VaasSdk\Exceptions\TimeoutException;
use VaasSdk\Exceptions\VaasConnectionClosedException;
use VaasSdk\Exceptions\VaasInvalidStateException;
use VaasSdk\Message\AuthRequest;
use WebSocket\Client;

class VaasConnection
{
    public Client $WebSocketClient;
    public string $SessionId;
    private Future $connection;
    private int $waitTimeoutInSeconds = 600;

    public function __construct(
        string $url, Client $WebSocketClient = null,
        private AuthenticatorInterface $authenticator,
        private Cache $responses = new Cache(),
        private LoggerInterface $logger)
    {
        $this->authenticator = $authenticator;
        $this->Connect();
        if (!isset($WebSocketClient))
            $this->WebSocketClient = new Client($url, [
                "filter" => [
                    'text', 'binary', 'ping'
                ],
                "return_obj" => true
            ]);
        else
            $this->WebSocketClient = $WebSocketClient;
        $this->WebSocketClient->ping();
    }

    public function Connect(string $token): void {
        $webSocket = $this->GetConnectedWebsocket();

        if ($token)
            $authRequest = new AuthRequest($token);
        else 
            $authRequest = new AuthRequest($this->authenticator->getToken());

        $webSocket->send(json_encode($authRequest));
    }

    public function GetConnectedWebsocket(): Client
    {
        if (!$this->WebSocketClient) {
            throw new VaasInvalidStateException("connect() was not called");
        }
        if (!$this->WebSocketClient->isConnected()) {
            throw new VaasConnectionClosedException();
        }
        return $this->WebSocketClient;
    }

    public function GetAuthenticatedWebsocket(): Client
    {
        $websocket = $this->GetConnectedWebsocket();
        if (!isset($this->SessionId) || !$this->SessionId) {
            throw new VaasInvalidStateException(
                "Not yet authenticated - connect() was not awaited"
                );
        }
        return $websocket;
    }

    private function handleResponse(): void {
        $start_time = time();

        $connection = $this->connection->await();
        assert($connection instanceof WebsocketClient);
        while (true) {
            if ((time() - $start_time) > $this->waitTimeoutInSeconds) {
                throw new TimeoutException();
            }
            $result = null;
            try {
                $result = $connection->
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
        }
    }
}