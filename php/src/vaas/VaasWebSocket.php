<?php

namespace VaasSdk;

use Amp\Future;
use Amp\Websocket\Client\WebsocketConnection;
use Error;
use JsonMapper;
use Ramsey\Uuid\Rfc4122\UuidV4;
use VaasSdk\Message\AuthRequest;
use VaasSdk\Message\AuthResponse;
use VaasSdk\Message\BaseMessage;
use VaasSdk\Message\BaseVerdictRequest;
use VaasSdk\Message\Kind;
use WebSocket\Exception;
use function Amp\async;
use function Amp\Websocket\Client\connect;

class VaasWebSocket {
    private string $url;
    private AuthenticatorInterface $authenticator;

    private ?Future $futureConnection = null;
    private function getConnection(): WebsocketConnection { return $this->futureConnection->await(); }
    private ?Future $futureSessionId = null;
    private function getSessionId(): string { return $this->futureSessionId->await(); }


    public function __construct(string $url, AuthenticatorInterface $authenticator) {
        $this->url = $url;
        $this->authenticator = $authenticator;
    }

    public function sendRequest(BaseVerdictRequest $request, string $requestId = null): void {
        $this->connectAndAuthenticate()->await();
        $connection = $this->getConnection();
        $request->session_id = $this->getSessionId();
        if ($requestId == null) {
            $requestId = UuidV4::getFactory()->uuid4()->toString();
        }
        $request->guid = $requestId;
        // TODO: add request to dictionary requests<string, Future>
        $connection->sendText(json_encode($request));
        // TODO: catch exception
    }

    private function connectAndAuthenticate(): Future {
        if ($this->futureConnection == null) {
            $this->futureConnection = async(static function($url) { return connect($url); }, $this->url);
            $this->futureSessionId = $this->futureConnection->map(function($connection)  { return $this->authenticate($connection, $this->authenticator); });
        }
        return $this->futureSessionId;
    }

    private function authenticate($connection, $authenticator): string {
        $this->sendAuthRequest($connection, $authenticator);
        foreach ($connection as $message) {
            $parsedMessage = $this->parseMessage($message);
            print_r($parsedMessage);
            if ($parsedMessage instanceof AuthResponse) {
                print("sessionId " . $parsedMessage->session_id);
                return $parsedMessage->session_id;
            }
        }
        // TODO: Use correct exception
        throw new Exception();
    }

    private function sendAuthRequest($connection, $authenticator): void {
        $token = $authenticator->getToken();
        $authRequest = new AuthRequest($token);
        $connection->sendText(json_encode($authRequest));
    }

    private function parseMessage($message) {
        $jsonObject = json_decode($message->read());
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
                    new \VaasSdk\Message\Error()
                );
        }
        throw new Error("TODO");
    }

    private function disconnect(): void {
        $this->futureSessionId = null;
        $this->futureConnection = null;
    }
}
