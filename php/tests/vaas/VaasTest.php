<?php

namespace VaasTesting;

use Dotenv\Dotenv;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use VaasSdk\Authentication\Authenticator;
use VaasSdk\Authentication\GrantType;
use VaasSdk\Options\AuthenticationOptions;
use VaasSdk\Options\VaasOptions;
use VaasSdk\Vaas;
use VaasSdk\Verdict;

final class VaasTest extends TestCase
{
    use ProphecyTrait;

    const MALICIOUS_HASH = "ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2";
    const MALICIOUS_URL = "https://secure.eicar.org/eicar.com.txt";

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

    private function getVaas(bool $useCache = false, bool $useHashLookup = true): Vaas
    {
        $credentials = new AuthenticationOptions(
            GrantType::CLIENT_CREDENTIALS,
            $_ENV["CLIENT_ID"],
            $_ENV["CLIENT_SECRET"]
        );

        $options = new VaasOptions(
            $useHashLookup,
            $useCache,
            $_ENV["VAAS_URL"],
            $_ENV["TOKEN_URL"]
        );

        $authenticator = new Authenticator($credentials, $options);

        return new Vaas($authenticator, $options);
    }

    public function testForSha256_WithMaliciousSha256_GetsMaliciousResponse(): void
    {
        $vaas = $this->getVaas();
        
        $verdict = $vaas->forSha256Async(self::MALICIOUS_HASH)->await();

        $this->assertEquals(Verdict::MALICIOUS, $verdict->Verdict);
        $this->assertEqualsIgnoringCase(self::MALICIOUS_HASH, $verdict->Sha256);
    }
}