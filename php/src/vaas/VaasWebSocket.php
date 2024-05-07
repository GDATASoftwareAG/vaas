<?php

namespace VaasSdk;

use Amp\DeferredFuture;
use Amp\Future;
use Amp\Websocket\Client\WebsocketConnection;
use Amp\Websocket\WebsocketCloseInfo;
use Error;
use JsonMapper;
use VaasSdk\Message\AuthRequest;
use VaasSdk\Message\AuthResponse;
use VaasSdk\Message\BaseMessage;
use VaasSdk\Message\BaseVerdictRequest;
use VaasSdk\Message\Kind;
use VaasSdk\Message\VerdictResponse;
use WebSocket\Exception;
use function Amp\async;
use function Amp\Websocket\Client\connect;

class VaasWebSocket
{
    private string $url;
    private AuthenticatorInterface $authenticator;

    private ?Future $futureConnection = null;

    private function getConnection(): WebsocketConnection
    {
        return $this->futureConnection->await();
    }

    private ?Future $futureSessionId = null;

    private function getSessionId(): string
    {
        return $this->futureSessionId->await();
    }

    /** @var $requests array<string, Future> */
    private array $requests = [];

    public function __construct(string $url, AuthenticatorInterface $authenticator)
    {
        $this->url = $url;
        $this->authenticator = $authenticator;
    }

    public function sendRequest(BaseVerdictRequest $request): Future
    {
        $this->connectAndAuthenticate()->await();
        $connection = $this->getConnection();
        $request->session_id = $this->getSessionId();

        $deferredResponse = new DeferredFuture();
        $this->requests[$request->guid] = $deferredResponse;

        $connection->sendText(json_encode($request));

        return $deferredResponse->getFuture();

        // TODO: catch exception
    }

    private function connectAndAuthenticate(): Future
    {
        if ($this->futureConnection == null) {
            $this->futureConnection = async(static function ($url) {
                return connect($url);
            }, $this->url);
            $this->futureSessionId = $this->futureConnection->map(function ($connection) {
                $connection->onClose(function (int $clientId, WebsocketCloseInfo $closeInfo) {
                    $this->onClose($clientId, $closeInfo);
                });
                return $this->authenticate($connection, $this->authenticator);
            });
            // TODO: private field?
            async(function () {
                $this->readMessages();
            });
        }
        return $this->futureSessionId;
    }

    private function authenticate($connection, $authenticator): string
    {
        $this->sendAuthRequest($connection, $authenticator);
        foreach ($connection as $message) {
            $parsedMessage = $this->parseMessage($message);
            print_r($parsedMessage);
            if ($parsedMessage instanceof AuthResponse) {
                // TODO: Log "authenticated with session id"
                return $parsedMessage->session_id;
            }
        }
        // TODO: Use correct exception
        throw new Exception();
    }

    private function sendAuthRequest($connection, $authenticator): void
    {
        $token = $authenticator->getToken();
        $authRequest = new AuthRequest($token);
        $connection->sendText(json_encode($authRequest));
    }

    private function parseMessage($message): BaseMessage
    {
        $jsonObject = json_decode($message->read());
        // TODO: Log debug
        print_r($jsonObject);
        $baseMessage = (new JsonMapper())->map(
            $jsonObject,
            new BaseMessage()
        );
        switch ($baseMessage->kind) {
            case Kind::AuthResponse:
                return (new JsonMapper())->map(
                    $jsonObject,
                    new AuthResponse()
                );
            case Kind::Error:
                return (new JsonMapper())->map(
                    $jsonObject,
                    new Message\Error()
                );
            case Kind::VerdictResponse:
                return (new JsonMapper())->map(
                    $jsonObject,
                    new VerdictResponse()
                );
        }
        // TODO
        throw new Error("TODO");
    }

    private function readMessages(): void
    {
        foreach ($this->getConnection() as $message) {
            $parsedMessage = $this->parseMessage($message);
            print_r($parsedMessage);
            // TODO: Use requestId in all messages
            $requestId = $parsedMessage->guid;
            if (!key_exists($requestId, $this->requests)) {
                // TODO: Log
                continue;
            }
            $deferredResponse = $this->requests[$requestId];
            unset($this->requests[$requestId]);
            // TODO: Handle errors
            $deferredResponse->complete($parsedMessage);
        }
    }

    private function onClose(int $clientId, WebsocketCloseInfo $closeInfo): void
    {
        // TODO
    }

    private function disconnect(): void
    {
        $this->futureSessionId = null;
        $this->futureConnection = null;
    }

    /**
     * @param string $requestId
     * @return Future<VerdictResponse>
     */
    public function waitForVerdict(string $requestId): Future
    {
        // TODO: Throw if not connected/authenticated
        $deferredResponse = new DeferredFuture();
        $this->requests[$requestId] = $deferredResponse;
        return $deferredResponse->getFuture();
    }
}
