<?php

namespace VaasSdk;

use Amp\Cache\LocalCache;
use Amp\CancelledException;
use Amp\DeferredCancellation;
use Amp\DeferredFuture;
use Amp\Future;
use Amp\Websocket\Client\WebsocketConnection;
use Exception;
use JsonMapper;
use JsonMapper_Exception;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Revolt\EventLoop;
use VaasSdk\Authentication\AuthenticatorInterface;
use VaasSdk\Exceptions\VaasAuthenticationException;
use VaasSdk\Exceptions\VaasClientException;
use VaasSdk\Exceptions\VaasConnectionClosedException;
use VaasSdk\Exceptions\VaasInvalidStateException;
use VaasSdk\Exceptions\VaasServerException;
use VaasSdk\Message\AuthRequest;
use VaasSdk\Message\AuthResponse;
use VaasSdk\Message\BaseMessage;
use VaasSdk\Message\Error;
use VaasSdk\Message\Kind;
use VaasSdk\Message\VerdictResponse;

use function Amp\async;
use function Amp\Websocket\Client\connect;

class VaasConnection
{
    public string $SessionId;

    private WebsocketConnection $WebSocketClient;
    private int $waitTimeoutInSeconds = 600;
    private string $url = "wss://gateway.production.vaas.gdatasecurity.de";
    private AuthenticatorInterface $authenticator;
    private LocalCache $responses;
    private LoggerInterface $logger;
    private ?Future $loop;
    private ?DeferredCancellation $loopCancellation;

    public function __construct() {
        $this->responses = new LocalCache();
        $this->loopCancellation = new DeferredCancellation();
    }

    public function close(): void {
        if ($this->loopCancellation != null) {
            $this->loopCancellation->cancel();
        }
        $this->loop->ignore();
    }

    public function withAuthenticator(AuthenticatorInterface $authenticator): VaasConnection {
        $this->authenticator = $authenticator;
        return $this;
    }

    public function withConnection(WebsocketConnection $WebSocketClient): VaasConnection {
        $this->WebSocketClient = $WebSocketClient;
        return $this;
    }

    public function withUrl(string $url): VaasConnection {
        $this->url = $url;
        return $this;
    }
    
    public function withLogger(LoggerInterface $logger): VaasConnection {
        $this->logger = $logger;
        return $this;
    }

    public function withTimeout(int $timeoutInSeconds): VaasConnection {
        $this->waitTimeoutInSeconds = $timeoutInSeconds;
        return $this;
    }

    public function build(): VaasConnection {
        if (!isset($this->WebSocketClient)) {
            $this->WebSocketClient = connect($this->url);
        }
        $this->loop = async(function() {
            $this->handleResponse();
        })->catch(function($e) {
            if (!$e instanceof CancelledException) {
                $this->logger->error("Error", ["error" => $e]);
            }
            $futures = $this->responses->getIterator();
            foreach($futures as $future) {
                $future->error($e);
            }
        });
        if (isset($this->authenticator)) {
            $this->Connect();
        }
        if (!isset($this->logger)) {
            $this->logger = new NullLogger();
        }
        return $this;
    }

    public function Connect(string $token = ""): void {
        if ($token === "" && !isset($this->authenticator)) {
            throw new VaasInvalidStateException("Authenticator not set and no token given");
        }

        if ($token !== "")
            $authRequest = new AuthRequest($token);
        else 
            $authRequest = new AuthRequest($this->authenticator->getToken());

        $futureResponse = $this->SendAuthRequest(json_encode($authRequest));
        $authResponse = $futureResponse->await();
        $this->SessionId = $authResponse->session_id;
    }

    private function SendAuthRequest(string $message): Future {
        $webSocket = $this->GetConnectedWebsocket();
        return $this->Send($webSocket, $message, AuthRequest::class);
    }

    public function SendRequest(string $message, $requestId): Future {
        $webSocket = $this->GetAuthenticatedWebsocket();
        return $this->Send($webSocket, $message, $requestId);
    }

    public function Send(WebsocketConnection &$webSocket,  string $message, $requestId): Future {
        $deferred = $this->GetResponse($requestId);
        EventLoop::delay($this->waitTimeoutInSeconds, function() use ($deferred, $requestId) {
            if ($deferred->isComplete()) return;
            $this->responses->delete($requestId);
            $deferred->error(new VaasClientException("Request timed out"));
        });

        $webSocket->sendText($message);
        return $deferred->getFuture();
    }

    public function GetResponse($requestId): DeferredFuture {
        $future = new DeferredFuture();
        $this->responses->set($requestId, $future);
        return $future;
    }

    public function GetConnectedWebsocket(): WebsocketConnection
    {
        if (!isset($this->WebSocketClient)) {
            foreach($this->responses->getIterator() as $future) {
                $future->error(new VaasInvalidStateException("connect() was not called"));
            }
            throw new VaasInvalidStateException("connect() was not called");
        }
        if ($this->WebSocketClient->isClosed()) {
            foreach($this->responses->getIterator() as $future) {
                $future->error(new VaasConnectionClosedException());
            }
            throw new VaasConnectionClosedException();
        }
        return $this->WebSocketClient;
    }
    
    public function GetAuthenticatedWebsocket(): WebsocketConnection
    {
        $websocket = $this->GetConnectedWebsocket();
        if (!isset($this->SessionId) || !$this->SessionId) {
            throw new VaasInvalidStateException(
                "Not yet authenticated - connect() was not awaited"
                );
        }
        return $websocket;
    }

    public function setTimeout(int $timeoutInSeconds): void {
        $this->waitTimeoutInSeconds = $timeoutInSeconds;
    }

    private function handleResponse(): void {
        $mapper = new JsonMapper();
        $mapper->bStrictObjectTypeChecking = false;
        $connection = $this->GetConnectedWebsocket();
        while ($message = $connection->receive($this->loopCancellation->getCancellation())) {
            if ($message == null) continue;
            if (!$message->isText()) continue;
            $messageText = $message->read($this->loopCancellation->getCancellation());
            if ($messageText == null) throw new VaasConnectionClosedException();

            $this->logger->debug("Result", json_decode($messageText, true));
            $resultObject = json_decode($messageText);
            $baseMessage = $mapper->map($resultObject, BaseMessage::class);
            try {
                switch($baseMessage->kind) {
                    case Kind::AuthResponse:
                        $authResponse = $mapper->map($resultObject, AuthResponse::class);
                        assert($authResponse instanceof AuthResponse);
                        $futureResponse = $this->responses->get(AuthRequest::class);
                        if ($futureResponse == null) {
                            throw new VaasClientException("No future response found for auth request");
                        }
                        $this->responses->delete(AuthRequest::class);
                        assert($futureResponse instanceof DeferredFuture);
                        if ($authResponse->success === false) {
                            $futureResponse->error(new VaasAuthenticationException("Authentication failed"));
                        } else {
                            $futureResponse->complete($authResponse);
                        }
                        $this->responses->delete(AuthRequest::class);
                        break;
                    case Kind::VerdictResponse:
                        $verdictResponse = $mapper->map($resultObject, VerdictResponse::class);
                        $futureResponse = $this->ValidateResponseAndGetFuture($verdictResponse);
                        if ($futureResponse == null) {
                            break;
                        }
                        $futureResponse->complete($verdictResponse);
                        break;
                    case Kind::Error:
                        $errorResponse = $mapper->map($resultObject, Error::class);
                        $futureResponse = $this->ValidateResponseAndGetFuture($errorResponse);
                        if ($futureResponse == null) {
                            break;
                        }
                        $futureResponse->error($this->_handleWebSocketErrorResponse($errorResponse));
                        break;
                    default:
                        throw new VaasServerException("Unknown message kind: " . $baseMessage->kind);
                };
            } catch (JsonMapper_Exception $e) {
                throw new VaasServerException("Error parsing received message: " . $e->getMessage());
            }
        }
    }

    private function ValidateResponseAndGetFuture(Error|VerdictResponse $message): ?DeferredFuture {
        $requestId = $message->requestId ?? $message->guid;

        if (isset($requestId) == null && $message instanceof VerdictResponse) {
            foreach($this->responses->getIterator() as $future) {
                $future->error(new VaasServerException("No guid found in verdict response"));
            }
        }
        if ($requestId == null && $message instanceof Error) {
            foreach($this->responses->getIterator() as $future) {
                $future->error(new VaasClientException($message->problem_details->detail));
            }
            return null;
        }
        $futureResponse = $this->responses->get($requestId);
        if ($futureResponse == null) {
            foreach($this->responses->getIterator() as $future) {
                $future->error(new VaasClientException("No future response found for guid: " .$requestId));
            }
        }
        $this->responses->delete($requestId);
        return $futureResponse;
    }

    private function _handleWebSocketErrorResponse(Error $errorResponse): Exception
    {
        if (isset($errorResponse->problem_details->detail)) {
            $details = $errorResponse->problem_details->detail;
        } else {
            $details = null;
        }
        $errorType = $errorResponse->type;
        if ($errorType == "ClientError") {
            return new VaasClientException($details);
        }
        return new VaasServerException($details);
    }
}