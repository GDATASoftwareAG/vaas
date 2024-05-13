<?php

namespace VaasSdk;

use Amp\DeferredFuture;
use Amp\Future;
use Amp\Websocket\Client\WebsocketConnection;
use Amp\Websocket\WebsocketClosedException;
use Amp\Websocket\WebsocketCloseInfo;
use Closure;
use JsonMapper;
use JsonMapper_Exception;
use Psr\Log\LoggerInterface;
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

/** Provides a connection-free abstraction of the Websocket communication with the Vaas backend. */
class VaasWebSocket
{
    private string $url;
    private AuthenticatorInterface $authenticator;
    private LoggerInterface $logger;
    private Closure $connect;

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

    public function __construct(string $url, AuthenticatorInterface $authenticator, LoggerInterface $logger, ?Closure $connect = null)
    {
        $this->url = $url;
        $this->authenticator = $authenticator;
        $this->logger = $logger;
        $this->connect = $connect ?? connect(...);
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

        $futureResponse = $this->waitForVerdict($request->guid);

        $connection->sendText(json_encode($request));
        // TODO: catch WebsocketClosedException and retry?

        return $futureResponse;
    }

    private function connectAndAuthenticate(): Future
    {
        if ($this->futureConnection == null) {
            $this->futureConnection = async(function ($url) {
                $this->logger->debug("Connecting");
                $connection = ($this->connect)($url);
                $this->logger->debug("Connected");
                return $connection;
            }, $this->url);
            $connection = $this->futureConnection->await();
            $connection->onClose(function (int $clientId, WebsocketCloseInfo $closeInfo) {
                $this->onClose($clientId, $closeInfo);
            });
            // TODO: private field
            $futureReadMessages = async($this->readMessages(...));
            $this->futureSessionId = async(fn () => $this->authenticate($connection, $this->authenticator));
//            async(function () {
//                try {
//                    $this->readMessages();
//                    // TODO: Ist das hier richtig? Throwen bringt hier nichts (?)
////                    $this->failRequests(new VaasClientException("Server connection closed unexpectedly."));
//                } catch (Throwable $e) {
//                    // TODO: Ist das hier richtig? Throwen bringt hier nichts (?)
////                    $this->failRequests(new VaasClientException($e->getMessage()));
//                } finally {
//                    $this->disconnect();
//                }
//            });
        }
        return $this->futureSessionId;
    }

    private function onClose(int $clientId, WebsocketCloseInfo $closeInfo): void
    {
        // TODO
    }

    /**
     * Authenticate towards the server.
     * @param $connection
     * @param $authenticator
     * @return string The session id.
     * @throws VaasAuthenticationException
     * @throws VaasServerException
     */
    private function authenticate($connection, $authenticator): string
    {
        $this->logger->debug("Authenticating");
        $futureVerdictResponse = $this->waitForVerdict(AuthResponse::class);
        $this->sendAuthRequest($connection, $authenticator);
        $verdictResponse = $futureVerdictResponse->await();
        if (!$verdictResponse->success) {
            throw new VaasAuthenticationException("Authentication failed");
        }
        $sessionId = $verdictResponse->session_id;
        $this->logger->debug("Authenticated with session ID " . $sessionId);
        return $sessionId;
    }

    private function sendAuthRequest($connection, $authenticator): void
    {
        $token = $authenticator->getToken();
        $authRequest = new AuthRequest($token);
        $connection->sendText(json_encode($authRequest));
    }

    /**
     * Parse a single message received from the server.
     * @throws VaasServerException
     */
    private function parseMessage($message): BaseMessage
    {
        $jsonObject = json_decode($message->read());
        $this->logger->debug("JSON to parse: " . print_r($jsonObject, true));
        try {
            $baseMessage = (new JsonMapper())->map(
                $jsonObject,
                new BaseMessage()
            );
            $parsedMessage = match ($baseMessage->kind) {
                Kind::AuthResponse => (new JsonMapper())->map(
                    $jsonObject,
                    new AuthResponse()
                ),
                Kind::Error => (new JsonMapper())->map(
                    $jsonObject,
                    new Message\Error()
                ),
                Kind::VerdictResponse => (new JsonMapper())->map(
                    $jsonObject,
                    new VerdictResponse()
                ),
                default => throw new VaasServerException("Received unknown message kind"),
            };
            $this->logger->debug("Parsed message: " . print_r($parsedMessage, true));
            return $parsedMessage;
        } catch (JsonMapper_Exception $e) {
            throw new VaasServerException("Error parsing received message: " . $e->getMessage());
        }
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
            $requestId = $parsedMessage instanceof AuthResponse ? AuthResponse::class : $parsedMessage->guid;
            if (!key_exists($requestId, $this->requests)) {
                // TODO: Template use
                $this->logger->warning("Received response for unknown request id");
                continue;
            }
            $deferredResponse = $this->requests[$requestId];
            switch ($parsedMessage->kind) {
                case Kind::AuthResponse:
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
        // TODO: Fail if not connected
        $deferredResponse = new DeferredFuture();
        $this->requests[$requestId] = $deferredResponse;
        return $deferredResponse->getFuture();
    }

    /**
     * Notify all currently pending requests that they cannot be fulfilled due to an irrecoverable connection error.
     * @param Throwable $e The error
     */
    private function failRequests(Throwable $e): void
    {
        foreach ($this->requests as $response) {
            $response->error($e);
        }
        $this->requests = [];
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
