<?php

namespace VaasTesting;

use Dotenv\Dotenv;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use VaasSdk\Authentication\Authenticator;
use VaasSdk\Authentication\GrantType;
use VaasSdk\Exceptions\VaasAuthenticationException;
use VaasSdk\Options\AuthenticationOptions;

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
    }

    public function testAuthenticatorWithInvalidClientCredentials_ThrowsAccessDeniedException(): void
    {
        $this->expectException(VaasAuthenticationException::class);
        $credentials = new AuthenticationOptions(
            GrantType::CLIENT_CREDENTIALS,
            "invalid",
            "invalid"
        );
        
        $authenticator = new Authenticator($credentials);
        $authenticator->getTokenAsync()->await();
    }

    public function testAuthenticatorWithInvalidPassword_ThrowsAccessDeniedException(): void
    {
        $this->expectException(VaasAuthenticationException::class);
        $credentials = new AuthenticationOptions(
            GrantType::PASSWORD,
            clientId: "invalid",
            userName: "invalid",
            password: "invalid"
        );

        $authenticator = new Authenticator($credentials);
        $authenticator->getTokenAsync()->await();
    }

    public function testAuthenticatorWithValidClientCredentials_ReturnsToken(): void
    {
        $credentials = new AuthenticationOptions(
            GrantType::CLIENT_CREDENTIALS,
            $_ENV["CLIENT_ID"],
            $_ENV["CLIENT_SECRET"]
        );

        $authenticator = new Authenticator($credentials);
        $token = $authenticator->getTokenAsync()->await();

        $this->assertNotNull($token);
    }

    public function testAuthenticatorWithValidPassword_ReturnsToken(): void
    {
        $credentials = new AuthenticationOptions(
            grantType: GrantType::PASSWORD,
            clientId: $_ENV["CLIENT_ID"],
            userName: $_ENV["VAAS_USER_NAME"],
            password: $_ENV["VAAS_PASSWORD"]
        );

        $authenticator = new Authenticator($credentials);
        $token = $authenticator->getTokenAsync()->await();

        $this->assertNotNull($token);
    }
}
