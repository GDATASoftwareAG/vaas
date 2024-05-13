<?php

namespace VaasTesting;

require_once __DIR__ . "/vendor/autoload.php";
require_once "testSetUp.php";

use Amp\Pipeline\Queue;
use Amp\Websocket\Client\WebsocketConnection;
use Amp\Websocket\WebsocketMessage;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use VaasSdk\Message\AuthResponse;
use VaasSdk\Message\Kind;
use VaasSdk\Message\Verdict;
use VaasSdk\Message\VerdictRequest;
use VaasSdk\Message\VerdictResponse;
use VaasSdk\VaasWebSocket;

function createWebsocketMessage(mixed $obj): WebsocketMessage
{
    return WebsocketMessage::fromText(json_encode($obj));
}

final class VaasWebsocketTest extends TestCase
{
    private LoggerInterface $logger;
    private WebsocketConnection $fakeWebsocketConnection;

    public function setUp(): void
    {
        setUpDotEnv();
        $this->logger = getDebugLogger();

        $ws = $this->createStub(WebsocketConnection::class);
        $this->fakeWebsocketConnection = $ws;
        $messages = new Queue();
        $this->mockQueueIterator($ws, $messages);
        $ws->method("sendText")->willReturnCallback(function (string $data) use ($messages) {
            $request = json_decode($data);
            $this->logger->debug("WebSocketClient::sendText " . print_r($request, true));
            switch (Kind::from($request->kind)) {
                case Kind::AuthRequest:
                    $response = new AuthResponse();
                    $response->success = true;
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
//            $this->logger->debug("Responding " . print_r($response, true));
            $messages->pushAsync(createWebsocketMessage($response));
        });
    }

    public function test_sendRequest_ifDisconnected(): void
    {
        $ws = $this->getVaasWebsocket();

        $response = $ws->sendRequest($this->getVerdictRequest())->await();

        $this->assertEquals(Verdict::MALICIOUS, $response->verdict);
    }

//    public function test_sendRequest(): void
//    {
//    }
//
//    public function test_sendRequest(): void
//    {
//    }
//
//    public function test_sendRequest(): void
//    {
//    }
//
//    public function test_sendRequest(): void
//    {
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
        return $this->fakeWebsocketConnection;
    }

// https://stackoverflow.com/questions/15907249/how-can-i-mock-a-class-that-implements-the-iterator-interface-using-phpunit

    /**
     * Setup methods required to mock an iterator
     *
     * @param Stub $iteratorMock The mock to attach the iterator methods to
     * @param array $items The mock data we're going to use with the iterator
     * @return Stub The iterator mock
     */
    function mockIterator(Stub $iteratorMock, array $items): Stub
    {
        $iteratorData = new \stdClass();
        $iteratorData->array = $items;
        $iteratorData->position = 0;

        $iteratorMock->expects($this->any())
            ->method('rewind')
            ->will(
                $this->returnCallback(
                    function () use ($iteratorData) {
                        $iteratorData->position = 0;
                    }
                )
            );

        $iteratorMock->expects($this->any())
            ->method('current')
            ->will(
                $this->returnCallback(
                    function () use ($iteratorData) {
                        return $iteratorData->array[$iteratorData->position];
                    }
                )
            );

        $iteratorMock->expects($this->any())
            ->method('key')
            ->will(
                $this->returnCallback(
                    function () use ($iteratorData) {
                        return $iteratorData->position;
                    }
                )
            );

        $iteratorMock->expects($this->any())
            ->method('next')
            ->will(
                $this->returnCallback(
                    function () use ($iteratorData) {
                        $iteratorData->position++;
                    }
                )
            );

        $iteratorMock->expects($this->any())
            ->method('valid')
            ->will(
                $this->returnCallback(
                    function () use ($iteratorData) {
                        return isset($iteratorData->array[$iteratorData->position]);
                    }
                )
            );

//        $iteratorMock->expects($this->any())
//            ->method('count')
//            ->will(
//                $this->returnCallback(
//                    function () use ($iteratorData) {
//                        return sizeof($iteratorData->array);
//                    }
//                )
//            );

        return $iteratorMock;
    }

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
                        $this->logger->debug("current() waiting");
                        $current = $iterator->current();
                        $this->logger->debug("current() got value");
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
