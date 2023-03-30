<?php

namespace VaasTesting;

require_once __DIR__ . "/vendor/autoload.php";

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

        $fakeWebsocket = $this->createStub(\WebSocket\Client::class);
        $fakeWebsocket->method('ping');
        $fakeWebsocket->method('send');
        $fakeWebsocket->method('isConnected')
            ->willReturn(true);
        $fakeWebsocket->method('receive')
            ->willReturn('{"kind": "AuthResponse", "success": false}');
        $vaasConnection = new VaasConnection("", $fakeWebsocket);

        (new Vaas("url"))->Connect("invalid", $vaasConnection);
    }

    public function testConnectionGetsClosedAfterConnecting_ThrowsVaasConnectionClosedException(): void
    {
        $this->expectException(VaasConnectionClosedException::class);

        $fakeWebsocket = $this->createStub(\WebSocket\Client::class);
        $fakeWebsocket->method('ping');
        $fakeWebsocket->method('send');
        $fakeWebsocket->method('isConnected')
            ->willReturn(true, true, false);
        $fakeWebsocket->method('receive')
            ->willReturn('{"kind": "AuthResponse", "success": true, "session_id": "id"}');
        $vaasConnection = new VaasConnection("", $fakeWebsocket);

        $vaas = new Vaas("url", new NullLogger());
        $vaas->Connect("valid", $vaasConnection);
        $vaas->ForSha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
    }

    public function testForSha256CallBeforeConnection_ThrowsVaasInvalidStateException(): void
    {
        $this->expectException(VaasInvalidStateException::class);
        $vaas = new Vaas("url");
        $vaas->ForSha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
    }
}
