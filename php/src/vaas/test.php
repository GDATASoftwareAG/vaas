<?php

require 'vendor/autoload.php';

use VaasSdk\ClientCredentialsGrantAuthenticator;
use VaasSdk\Message\AuthRequest;
use VaasSdk\Message\AuthResponse;
use VaasSdk\Message\BaseMessage;
use VaasSdk\Message\Kind;
use function Amp\async;
use function Amp\Websocket\Client\connect;

$url = "wss://gateway.develop.vaas.gdatasecurity.de";

$authenticator = new ClientCredentialsGrantAuthenticator(
    "vaas-integration-test",
    "",
    "https://account-staging.gdata.de/realms/vaas-develop/protocol/openid-connect/token"
);

$future = async(static function($url, $authenticator) {
    connectAndAuthenticate($url, $authenticator);
}, $url, $authenticator);
print ".";
$cancellation = new Amp\TimeoutCancellation(10);
// Amp\delay(5);
$future->await($cancellation);

function connectAndAuthenticate($url, $authenticator): void {
    $connection = connect($url);
    authenticate($connection, $authenticator);
}

function authenticate($connection, $authenticator): void {
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

function sendAuthRequest($connection, $authenticator): void {
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
