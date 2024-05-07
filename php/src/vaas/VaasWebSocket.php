<?php

namespace VaasSdk;

use Amp\DeferredFuture;
use Amp\Future;
use Amp\Websocket\Client\WebsocketConnection;
use Amp\Websocket\WebsocketClosedException;
use JsonMapper;
use JsonMapper_Exception;
use Throwable;
use VaasSdk\Exceptions\VaasAuthenticationException;
use VaasSdk\Exceptions\VaasClientException;
use VaasSdk\Exceptions\VaasServerException;
use VaasSdk\Message\AuthRequest;
use VaasSdk\Message\AuthResponse;
use VaasSdk\Message\BaseMessage;
use VaasSdk\Message\BaseVerdictRequest;
use VaasSdk\Message\Kind;
use VaasSdk\Message\VerdictResponse;
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

    /**
     * Send a verdict request to the server. Returns asynchronously the corresponding response, or an error.
     * @param BaseVerdictRequest $request
     * @return Future<VerdictResponse>
     * @throws WebsocketClosedException If the connection is unexpectedly closed while sending the request
     */
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
                return $this->authenticate($connection, $this->authenticator);
            });
            // TODO: private field?
            async(function () {
                try {
                    $this->readMessages();
                    $this->notifyFutures(new VaasClientException("Server connection closed unexpectedly."));
                } catch (Throwable $e) {
                    $this->notifyFutures(new VaasClientException($e->getMessage()));
                } finally {
                    $this->disconnect();
                }
            });
        }
        return $this->futureSessionId;
    }

    /**
     * Authenticate towards the server.
     * @return string The session id.
     * @throws VaasClientException
     * @throws JsonMapper_Exception
     * @throws VaasAuthenticationException
     */
    private function authenticate($connection, $authenticator): string
    {
        $this->sendAuthRequest($connection, $authenticator);
        foreach ($connection as $message) {
            $parsedMessage = $this->parseMessage($message);
            if ($parsedMessage instanceof AuthResponse) {
                // TODO: Log "authenticated with session id"
                return $parsedMessage->session_id;
            }
        }
        throw new VaasAuthenticationException("Authentication failed");
    }

    private function sendAuthRequest($connection, $authenticator): void
    {
        $token = $authenticator->getToken();
        $authRequest = new AuthRequest($token);
        $connection->sendText(json_encode($authRequest));
    }

    /**
     * Parse a single message received from the server.
     * @throws JsonMapper_Exception
     * @throws VaasClientException
     */
    private function parseMessage($message): BaseMessage
    {
        $jsonObject = json_decode($message->read());
        // TODO: Log debug
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
        throw new VaasClientException("Unknown websocket message");
    }

    /**
     * Continuously reads messages from the websocket. Returns when the websocket connection is shutdown, or has failed.
     * @throws JsonMapper_Exception
     * @throws VaasClientException
     */
    private function readMessages(): void
    {
        foreach ($this->getConnection() as $message) {
            $parsedMessage = $this->parseMessage($message);
            // TODO: Use requestId in all messages
            $requestId = $parsedMessage->guid;
            if (!key_exists($requestId, $this->requests)) {
                // TODO: Log warning
                continue;
            }
            $deferredResponse = $this->requests[$requestId];
            switch ($parsedMessage->kind) {
                case Kind::VerdictResponse:
                    $deferredResponse->complete($parsedMessage);
                    break;
                case Kind::Error:
                    $deferredResponse->error(self::convertWebSocketErrorResponse($parsedMessage));
                    break;
                default:
                    $deferredResponse->error(new VaasServerException("Invalid response received from server"));
                    break;
            }
            // Only delete from pending after having it completed/errored, in case the switch above fails
            unset($this->requests[$requestId]);
        }
    }

    /**
     * Disconnect the current websocket session immediately.
     */
    private function disconnect(): void
    {
        $this->futureSessionId = null;
        $this->futureConnection = null;
        $this->requests = [];
    }

    /**
     * Asynchronously waits for a verdict response with the given requestId. Returns the corresponding response.
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

    /**
     * Notify all currently pending futures that their request cannot be fulfilled due to an error.
     * @param VaasClientException $e The error
     */
    private function notifyFutures(VaasClientException $e): void
    {
        foreach ($this->requests as $response) {
            $response->error($e);
        }
    }

    private static function convertWebSocketErrorResponse(Message\Error $errorResponse): VaasClientException|VaasServerException
    {
        $details = $errorResponse->problem_details->detail ?? null;
        $errorType = $errorResponse->type;
        if ($errorType == "ClientError") {
            return new VaasClientException($details);
        }
        return new VaasServerException($details);
    }
}
