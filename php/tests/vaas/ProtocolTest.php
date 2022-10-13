<?php

namespace VaasTesting;

require_once __DIR__ . "/vendor/autoload.php";

use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use VaasSdk\Vaas;
use Mockery;
use VaasSdk\Exceptions\VaasAccessDeniedException;
use VaasSdk\Exceptions\VaasConnectionClosedException;
use VaasSdk\Exceptions\VaasInvalidStateException;
use WebSocket\Client;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
final class ProtocolTest extends TestCase
{
    use ProphecyTrait;

    public function tearDown(): void
    {
        Mockery::close();
    }

    public function testForConnectWithInvalidToken_ThrowsAccessDeniedException(): void
    {
        $this->expectException(VaasAccessDeniedException::class);
        $fakeWebsocket = Mockery::mock("overload:WebSocket\Client");
        $fakeWebsocket->shouldReceive('ping')
            ->once();
        $fakeWebsocket->shouldReceive('send')
            ->withAnyArgs();
        $fakeWebsocket->shouldReceive('isConnected')
            ->andReturn(true);
        $fakeWebsocket->shouldReceive('receive')
            ->andReturn('{"kind": "AuthResponse", "success": false}');
        (new Vaas("url"))->Connect("invalid");
    }

    public function testConnectionGetsClosedAfterConnecting_ThrowsVaasConnectionClosedException(): void
    {
        $this->expectException(VaasConnectionClosedException::class);
        $fakeWebsocket = Mockery::mock("overload:WebSocket\Client");
        $fakeWebsocket->shouldReceive('ping')
            ->once();
        $fakeWebsocket->shouldReceive('send');
        $fakeWebsocket->shouldReceive('isConnected')
            ->andReturnValues([true, false]);
        $fakeWebsocket->shouldReceive('receive')
            ->andReturn('{"kind": "AuthResponse", "success": true, "session_id": "id"}');
        $vaas = new Vaas("url");
        $vaas->Connect("valid");
        $vaas->ForSha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
    }

    public function testForSha256CallBeforeConnection_ThrowsVaasInvalidStateException(): void
    {
        $this->expectException(VaasInvalidStateException::class);
        $fakeWebsocket = Mockery::mock("overload:WebSocket\Client");
        $fakeWebsocket->shouldReceive('ping')
            ->once();
        $fakeWebsocket->shouldReceive('isConnected')
            ->once()
            ->andReturn(true);
        $vaas = new Vaas("url");
        $vaas->ForSha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
    }
}