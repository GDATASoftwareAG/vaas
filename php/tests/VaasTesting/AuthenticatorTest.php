<?php

namespace VaasTesting;

use Dotenv\Dotenv;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use VaasSdk\Authentication\ClientCredentialsGrantAuthenticator;
use VaasSdk\Authentication\ResourceOwnerPasswordGrantAuthenticator;
use VaasSdk\Exceptions\VaasAuthenticationException;

final class AuthenticatorTest extends TestCase
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
        if (getenv("VAAS_USER_NAME") !== false) {
            $_ENV["VAAS_USER_NAME"] = getenv("VAAS_USER_NAME");
        }
        if (getenv("VAAS_PASSWORD") !== false) {
            $_ENV["VAAS_PASSWORD"] = getenv("VAAS_PASSWORD");
        }
        if (getenv("VAAS_URL") !== false) {
            $_ENV["VAAS_URL"] = getenv("VAAS_URL");
        }
        if (getenv("TOKEN_URL") !== false) {
            $_ENV["TOKEN_URL"] = getenv("TOKEN_URL");
        }
        if (getenv("VAAS_CLIENT_ID") !== false) {
            $_ENV["VAAS_CLIENT_ID"] = getenv("VAAS_CLIENT_ID");
        }
        
        $this->assertNotNull($_ENV["CLIENT_ID"]);
        $this->assertNotNull($_ENV["CLIENT_SECRET"]);
        $this->assertNotNull($_ENV["VAAS_USER_NAME"]);
        $this->assertNotNull($_ENV["VAAS_PASSWORD"]);
        $this->assertNotNull($_ENV["VAAS_URL"]);
        $this->assertNotNull($_ENV["TOKEN_URL"]);
        $this->assertNotNull($_ENV["VAAS_CLIENT_ID"]);
    }

    public function testClientCredentialsGrantAuthenticator_withInvalidCredentials_ThrowsAccessDeniedException(): void
    {
        $this->expectException(VaasAuthenticationException::class);
        $authenticator = new ClientCredentialsGrantAuthenticator(
            clientId: "invalid",
            clientSecret: "invalid"
        );
        
        $authenticator->getTokenAsync();
    }

    public function testResourceOwnerPasswordGrantAuthenticator_withInvalidCredentials_ThrowsAccessDeniedException(): void
    {
        $this->expectException(VaasAuthenticationException::class);
        $authenticator = new ResourceOwnerPasswordGrantAuthenticator(
            clientId: "invalid",
            userName: "invalid",
            password: "invalid"
        );

        $authenticator->getTokenAsync();
    }

    public function testClientCredentialsGrantAuthenticator_withValidCredentials_ReturnsToken(): void
    {
        $authenticator = new ClientCredentialsGrantAuthenticator(
            clientId: $_ENV["CLIENT_ID"],
            clientSecret: $_ENV["CLIENT_SECRET"],
            tokenUrl: $_ENV["TOKEN_URL"]
        );
        
        $token = $authenticator->getTokenAsync();

        $this->assertNotNull($token);
    }

    public function testResourceOwnerPasswordGrantAuthenticator_withValidCredentials_ReturnsToken(): void
    {
        $authenticator = new ResourceOwnerPasswordGrantAuthenticator(
            clientId: $_ENV["VAAS_CLIENT_ID"],
            userName: $_ENV["VAAS_USER_NAME"],
            password: $_ENV["VAAS_PASSWORD"],
            tokenUrl: $_ENV["TOKEN_URL"]
        );

        $token = $authenticator->getTokenAsync();

        $this->assertNotNull($token);
    }
}
