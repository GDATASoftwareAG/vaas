<?php

namespace VaasTesting;

require_once __DIR__ . "/vendor/autoload.php";
require_once "testSetUp.php";

use Amp\Pipeline\Queue;
use Amp\Websocket\Client\WebsocketConnection;
use Amp\Websocket\WebsocketMessage;
use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\MockObject\Rule\AnyInvokedCount;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use VaasSdk\Exceptions\VaasAuthenticationException;
use VaasSdk\Message\AuthResponse;
use VaasSdk\Message\Kind;
use VaasSdk\Message\Verdict;
use VaasSdk\Message\VerdictRequest;
use VaasSdk\Message\VerdictResponse;
use VaasSdk\VaasWebSocket;
use function Amp\async;

function createWebsocketMessage(mixed $obj): WebsocketMessage
{
    return WebsocketMessage::fromText(json_encode($obj));
}

final class VaasWebsocketTest extends TestCase
{
    private LoggerInterface $logger;
    private WebsocketConnection $fakeWebsocketConnection;
    private AnyInvokedCount $sendTextSpy;
    private Queue $incomingMessages;
    private int $connectCounter = 0;

    /**
     * @throws Exception
     */
    public function setUp(): void
    {
        setUpDotEnv();
        $this->logger = getDebugLogger();

        // https://lyte.id.au/2014/03/01/spying-with-phpunit/
        $this->createWebsocketConnection();
    }

    private function createWebsocketConnection(): void
    {
        $this->fakeWebsocketConnection = $this->createStub(WebsocketConnection::class);
        $this->incomingMessages = new Queue(16);
        $this->mockQueueIterator($this->fakeWebsocketConnection, $this->incomingMessages);
    }

    private function mockDefaultBehavior(): void
    {
        $this->fakeWebsocketConnection
            ->expects($this->sendTextSpy = $this->any())
            ->method("sendText")->willReturnCallback($this->sendText(...));
    }

    private function sendText(string $data, bool $authSuccess = true): void
    {
        $request = json_decode($data);
        $this->logger->debug("WebSocketClient::sendText " . print_r($request, true));
        switch (Kind::from($request->kind)) {
            case Kind::AuthRequest:
                $response = new AuthResponse();
                $response->success = $authSuccess;
                $response->session_id = "0815";
                break;
            case Kind::VerdictRequest:
                $response = new VerdictResponse();
                $response->verdict = Verdict::MALICIOUS;
                $response->guid = $request->guid;
                break;
            default:
                return;
        }
        $this->incomingMessages->push(createWebsocketMessage($response));
    }

    public function test_sendRequest_ifDisconnected(): void
    {
        $this->mockDefaultBehavior();
        $ws = $this->getVaasWebsocket();

        $response = $ws->sendRequest($this->getVerdictRequest())->await();

        $this->assertEquals(Verdict::MALICIOUS, $response->verdict);
    }

    public function test_sendRequest_ifDisconnectedAndAuthenticationFails_throwsVaasAuthenticationException(): void
    {
        $this->fakeWebsocketConnection
            ->method("sendText")->willReturnCallback(fn ($data) => $this->sendText($data, false));
        $ws = $this->getVaasWebsocket();

        // sendRequest does not throw directly
        $future = $ws->sendRequest($this->getVerdictRequest());
        $this->expectException(VaasAuthenticationException::class);
        $this->expectExceptionMessage("Authentication failed");
        // the await does
        $future->await();
    }

    // sendRequest_ifDisconnectedAndConnectFails_retries
    // sendRequest_ifDisconnectedAndConnectFails_retriesUntilTimeout

    // sendRequest_ifSendFails_reconnectsAndRetries
    // sendRequest_ifSendFails_reconnectsAndRetriesUntilTimeout

    // sendRequest_ifDisconnectBeforeResponse_reconnectsAndRetries
    // sendRequest_ifDisconnectBeforeResponse_reconnectsAndRetriesUntilTimeout

    public function test_sendRequest_ifAuthenticated_usesExistingConnectionAndAuthentication(): void
    {
        $this->mockDefaultBehavior();
        $ws = $this->getVaasWebsocket();
        $response = $ws->sendRequest($this->getVerdictRequest())->await();

        $response = $ws->sendRequest($this->getVerdictRequest())->await();

        $this->assertSame(Verdict::MALICIOUS, $response->verdict);
        $this->assertSame(1, $this->connectCounter);
        $this->assertSame(3, $this->sendTextSpy->numberOfInvocations());
    }

    // waitForResponse_ifNotAuthenticated_throwsVaasServerException

//    public function test_sendRequest_ifNotAuthenticated_waitsForAuthentication()
//    {
//        $ws = $this->getVaasWebsocket();
//        $sentMessages = new Queue(16);
//        $this->fakeWebsocketConnection->method("sendText")->willReturnCallback(function (string $data) use ($sentMessages) {
//            $this->logger->debug("sendText " . $data);
//            $sentMessages->push($data);
//        });
//
//        $this->logger->debug(1);
//        $response1 = async(fn () => $ws->sendRequest($this->getVerdictRequest()));
//
//        $this->logger->debug(2);
//        $response2 = async(fn () => $ws->sendRequest($this->getVerdictRequest()));
//
//        $this->logger->debug(3);
//        $i = $sentMessages->iterate();
//        while ($i->continue()) {
//            $value = $i->getValue();
//            $this->logger->debug($value);
//            // TODO: Handle and return response
//            $this->incomingMessages->push(createWebsocketMessage($value));
//        }
//        $this->logger->debug(4);
//        $this->assertSame(Verdict::MALICIOUS, $response1->await()->verdict);
//        $this->assertSame(Verdict::MALICIOUS, $response2->await()->verdict);
//        $this->assertSame(1, $this->connectCounter);
//        $this->assertSame(3, $this->sendTextSpy->numberOfInvocations());
//    }

    private function getVaasWebsocket(): VaasWebSocket
    {
        return new VaasWebSocket($_ENV["VAAS_URL"], getClientCredentialsGrantAuthenticator(), $this->logger, $this->connect(...));
//        return new VaasWebSocket($_ENV["VAAS_URL"], getClientCredentialsGrantAuthenticator(), $this->logger);
    }

    private function getVerdictRequest(): VerdictRequest
    {
        return new VerdictRequest("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
    }

    private function connect(string $url): WebsocketConnection
    {
        $this->connectCounter++;
        return $this->fakeWebsocketConnection;
    }

    // Inspired by https://stackoverflow.com/questions/15907249/how-can-i-mock-a-class-that-implements-the-iterator-interface-using-phpunit

    /**
     * Setup methods required to mock an iterator
     *
     * @param Stub $iteratorMock The mock to attach the iterator methods to
     * @param Queue $queue The queue we're going to use with the iterator
     * @return Stub The iterator mock
     */
    function mockQueueIterator(Stub $iteratorMock, Queue $queue): Stub
    {
        $iterator = $queue->iterate()->getIterator();

        $iteratorMock->expects($this->any())
            ->method('rewind')
            ->will(
                $this->returnCallback(
                    function () use ($iterator) {
                        $iterator->rewind();
                    }
                )
            );

        $iteratorMock->expects($this->any())
            ->method('current')
            ->will(
                $this->returnCallback(
                    function () use ($iterator) {
                        $current = $iterator->current();
                        return $current;
                    }
                )
            );

        $iteratorMock->expects($this->any())
            ->method('key')
            ->will(
                $this->returnCallback(
                    function () use ($iterator) {
                        return $iterator->key();
                    }
                )
            );

        $iteratorMock->expects($this->any())
            ->method('next')
            ->will(
                $this->returnCallback(
                    function () use ($iterator) {
                        $iterator->next();
                    }
                )
            );

        $iteratorMock->expects($this->any())
            ->method('valid')
            ->will(
                $this->returnCallback(
                    function () use ($iterator) {
                        return $iterator->valid();
                    }
                )
            );

        return $iteratorMock;
    }
}
