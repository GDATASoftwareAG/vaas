<?php

namespace VaasTesting;

use Amp\Websocket\WebsocketMessage;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use Psr\Log\NullLogger;
use VaasSdk\Vaas;
use VaasSdk\Exceptions\VaasAuthenticationException;
use VaasSdk\Exceptions\VaasConnectionClosedException;
use VaasSdk\Exceptions\VaasInvalidStateException;
use VaasSdk\VaasConnection;

final class ProtocolTest extends TestCase
{
    use ProphecyTrait;

    public function testForConnectWithInvalidToken_ThrowsAccessDeniedException(): void
    {
        $this->expectException(VaasAuthenticationException::class);

        $fakeWebsocket = $this->createStub(\Amp\Websocket\Client\WebsocketConnection::class);
        $fakeWebsocket->method('ping');
        $fakeWebsocket->method('isClosed')
            ->willReturn(false);
        $fakeWebsocket->method('receive')
            ->willReturn(WebsocketMessage::fromText('{"kind": "AuthResponse", "success": false}'));
        $vaasConnection = new VaasConnection("", $fakeWebsocket);

        (new Vaas("url"))->build()->Connect("invalid", $vaasConnection);
    }

    public function testConnectionGetsClosedAfterConnecting_ThrowsVaasConnectionClosedException(): void
    {
        $this->expectException(VaasConnectionClosedException::class);

        $fakeWebsocket = $this->createStub(\Amp\Websocket\Client\WebsocketConnection::class);
        $fakeWebsocket->method('ping');
        $fakeWebsocket->method('isClosed')
            ->willReturn(false, true);
        $fakeWebsocket->method('receive')
            ->willReturn(WebsocketMessage::fromText('{"kind": "AuthResponse", "success": true, "session_id": "id"}'));
        $vaasConnection = (new VaasConnection())
            ->withConnection($fakeWebsocket)
            ->build();

        $vaas = (new Vaas())
            ->withUrl("wws://url.de")
            ->withVaasConnection($vaasConnection)
            ->build();
        $vaas->Connect("valid");
        $vaas->ForSha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
    }

    public function testConnectionGetsClosedBeforeConnect_ThrowsVaasConnectionClosedException(): void
    {
        $this->expectException(VaasConnectionClosedException::class);

        $fakeWebsocket = $this->createStub(\Amp\Websocket\Client\WebsocketConnection::class);
        $fakeWebsocket->method('ping');
        $fakeWebsocket->method('isClosed')
            ->willReturn(true);
        $fakeWebsocket->method('receive')
            ->willReturn(WebsocketMessage::fromText('{"kind": "AuthResponse", "success": true, "session_id": "id"}'));
        $vaasConnection = (new VaasConnection())
            ->withConnection($fakeWebsocket)
            ->build();

        $vaas = (new Vaas())
            ->withUrl("wws://url.de")
            ->withVaasConnection($vaasConnection)
            ->build();
        $vaas->Connect("valid");
    }

    public function testVerdictRequestSerializationTest(): void
    {
        $verdictRequest = new \VaasSdk\Message\VerdictRequest(
            "000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8",
            "guid",
            "sessionid"
        );
        $verdictRequest->use_cache = false;
        $verdictRequest->use_hash_lookup = false;

        $string = json_encode($verdictRequest);
        $this->assertEquals(
            '{"kind":"VerdictRequest","guid":"guid","session_id":"sessionid","use_hash_lookup":false,"use_cache":false,"sha256":"000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8"}',
            $string
        );
    }
}
