<?php

namespace VaasTesting;

require_once __DIR__ . "/vendor/autoload.php";

use Dotenv\Dotenv;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use Mockery;
use VaasSdk\ClientCredentialsGrantAuthenticator;
use VaasSdk\Exceptions\VaasAuthenticationException;

final class ClientCredentialsGrantAuthenticatorTest extends TestCase
{
    use ProphecyTrait;

    public function setUp(): void
    {
        $dotenv = Dotenv::createImmutable(__DIR__);
        $dotenv->safeLoad();
        if (getenv("CLIENT_ID") !== false) {
            $_ENV["CLIENT_ID"] = getenv("CLIENT_ID");
        }
        if (getenv("CLIENT_SECRET") !== false) {
            $_ENV["CLIENT_SECRET"] = getenv("CLIENT_SECRET");
        }
        if (getenv("VAAS_URL") !== false) {
            $_ENV["VAAS_URL"] = getenv("VAAS_URL");
        }
        if (getenv("TOKEN_URL") !== false) {
            $_ENV["TOKEN_URL"] = getenv("TOKEN_URL");
        }
    }

    public function testAuthenticatorWithInvalidCredentials_ThrowsAccessDeniedException(): void
    {
        $this->expectException(VaasAuthenticationException::class);
        $authenticator = new ClientCredentialsGrantAuthenticator("invalid", "invalid", $_ENV["TOKEN_URL"]);
        $authenticator->getToken();
    }
}