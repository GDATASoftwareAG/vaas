<?php

namespace VaasSdk;

use Amp\Future;
use Amp\Websocket\Client\WebsocketConnection;
use Ramsey\Uuid\Rfc4122\UuidV4;
use VaasSdk\Message\BaseVerdictRequest;
use VaasSdk\Message\VerdictResponse;
use function Amp\async;
use function Amp\Websocket\Client\connect;

class VaasWebSocket {
    private string $url;
    private AuthenticatorInterface $authenticator;

    private ?Future $futureConnection;
    private function getConnection(): WebsocketConnection { return $this->futureConnection->await(); }
    private ?Future $futureSessionId;
    private function getSessionId(): string { return $this->futureSessionId->await(); }


    public function __construct(string $url, AuthenticatorInterface $authenticator) {
        $this->url = $url;
        $this->authenticator = $authenticator;
    }

    public function sendRequest(BaseVerdictRequest $request, string $requestId = null): VerdictResponse {
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
            $this->futureConnection = async(static function($url) { connect($url); }, $this->url);
            $this->futureSessionId = $this->futureConnection->map(static function($connection)  { return $this->authenticate($connection); });
        }
        return $this->futureSessionId;
    }

    private function authenticate($connection, $authenticator): void {
        sendAuthRequest($connection, $authenticator);
        foreach ($connection as $message) {
            $parsedMessage = parseMessage($message);
            print_r($parsedMessage);
            if ($parsedMessage instanceof AuthResponse) {
                print("sessionId " . $parsedMessage->session_id);
                break;
            }
        }
    }

    private function sendAuthRequest($connection, $authenticator): void {
        $token = $authenticator->getToken();
        $authRequest = new AuthRequest($token);
        $connection->sendText(json_encode($authRequest));
    }

    function parseMessage($message) {
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
