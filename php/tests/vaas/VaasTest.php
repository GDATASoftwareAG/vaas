<?php

namespace VaasTesting;

use Amp\File\FilesystemException;
use Dotenv\Dotenv;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use VaasSdk\Authentication\Authenticator;
use VaasSdk\Authentication\GrantType;
use VaasSdk\Exceptions\VaasClientException;
use VaasSdk\Options\AuthenticationOptions;
use VaasSdk\Options\VaasOptions;
use VaasSdk\Vaas;
use VaasSdk\Verdict;
use function Amp\File\openFile;

final class VaasTest extends TestCase
{
    use ProphecyTrait;
    
    private Vaas $vaas;

    const MALICIOUS_HASH = "ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2";
    const EICAR_HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    const PUP_HASH = "42d6581dd0a2ba9bec6a40c5b7c85870a8019d7347c9130d24752ec5865f0732";
    const CLEAN_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const UNKNOWN_HASH = "23b85b080bda43cd0dd80f0386d66b8a5f3ca647441df0306d8c74ef035cfe93";
    
    const MALICIOUS_URL = "https://secure.eicar.org/eicar.com.txt";
    const PUP_URL = "http://amtso.eicar.org/PotentiallyUnwanted.exe";
    const CLEAN_URL = "https://www.gdata.de";

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
        
        $this->assertNotNull($_ENV["CLIENT_ID"]);
        $this->assertNotNull($_ENV["CLIENT_SECRET"]);
        $this->assertNotNull($_ENV["VAAS_URL"]);
        $this->assertNotNull($_ENV["TOKEN_URL"]);
        
        $this->vaas = $this->getVaas();
    }

    private function getVaas(bool $useCache = false, bool $useHashLookup = false): Vaas
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
        $verdict = $this->vaas->forSha256Async(self::MALICIOUS_HASH)->await();

        $this->assertEquals(Verdict::MALICIOUS, $verdict->verdict);
        $this->assertEqualsIgnoringCase(self::MALICIOUS_HASH, $verdict->sha256);
    }
    
    public function testForSha256_WithPupSha256_GetsPupResponse(): void
    {
        $verdict = $this->vaas->forSha256Async(self::PUP_HASH)->await();
        
        $this->assertEquals(Verdict::PUP, $verdict->verdict);
        $this->assertEqualsIgnoringCase(self::PUP_HASH, $verdict->sha256);
    }
    
    public function testForSha256_WithCleanSha256_GetsCleanResponse(): void
    {
        $verdict = $this->vaas->forSha256Async(self::CLEAN_HASH)->await();
        
        $this->assertEquals(Verdict::CLEAN, $verdict->verdict);
        $this->assertEqualsIgnoringCase(self::CLEAN_HASH, $verdict->sha256);
    }
    
    public function testForSha256_WithUnknownSha256_GetsUnknownResponse(): void
    {
        $vaas = $this->getVaas(false, false);
        
        $verdict = $vaas->forSha256Async(self::UNKNOWN_HASH)->await();
        
        $this->assertEquals(Verdict::UNKNOWN, $verdict->verdict);
        $this->assertEqualsIgnoringCase(self::UNKNOWN_HASH, $verdict->sha256);
    }
    
    public function testForSha256_WithInvalidSha256_ThrowsVaasClientException(): void
    {
        $this->expectException(VaasClientException::class);
        $this->expectExceptionMessage("Invalid SHA256 hash");
        
        $this->vaas->forSha256Async("invalid")->await();
    }
    
    public function testForUrl_WithMaliciousUrl_GetsMaliciousResponse(): void
    {        
        $verdict = $this->vaas->forUrlAsync(self::MALICIOUS_URL)->await();
        
        $this->assertEquals(Verdict::MALICIOUS, $verdict->verdict);
    }
    
    public function testForUrl_WithPupUrl_GetsPupResponse(): void
    {
        $verdict = $this->vaas->forUrlAsync(self::PUP_URL)->await();
        
        $this->assertEquals(Verdict::PUP, $verdict->verdict);
    }

    public function testForUrl_WithCleanUrl_GetsCleanResponse(): void
    {
        $verdict = $this->vaas->forUrlAsync(self::CLEAN_URL)->await();
        
        $this->assertEquals(Verdict::CLEAN, $verdict->verdict);
    }
    
    public function testForUrl_WithInvalidUrl_ThrowsVaasClientException(): void
    {
        $this->expectException(VaasClientException::class);
        $this->expectExceptionMessage("Invalid URL");
        
        $this->vaas->forUrlAsync("invalid")->await();
    }
    
    public function testForFile_WithCleanFile_GetsCleanResponse(): void
    {
        $verdict = $this->vaas->forFileAsync(__DIR__ . "/composer.json")->await();
        
        $this->assertEquals(Verdict::CLEAN, $verdict->verdict);
    }
    
    public function testForFile_WithMaliciousFile_GetsMaliciousResponse(): void
    {
        $file = file_get_contents(self::MALICIOUS_URL);
        file_put_contents(__DIR__ . "/eicar.com.txt", $file);
        
        $verdict = $this->vaas->forFileAsync(__DIR__ . "/eicar.com.txt")->await();
        unlink(__DIR__ . "/eicar.com.txt");
        
        $this->assertEquals(Verdict::MALICIOUS, $verdict->verdict);
        $this->assertEqualsIgnoringCase(self::EICAR_HASH, $verdict->sha256);
    }

    // TODO: Check why the sha256 hash is different
    /**
     * @group exclude
     */
    public function testForFile_WithPupFile_GetsPupResponse(): void
    {
        $file = file_get_contents(self::PUP_URL);
        file_put_contents(__DIR__ . "/PotentiallyUnwanted.exe", $file);
        
        $verdict = $this->vaas->forFileAsync(__DIR__ . "/PotentiallyUnwanted.exe")->await();
        unlink(__DIR__ . "/PotentiallyUnwanted.exe");

        $this->assertEqualsIgnoringCase(self::PUP_HASH, $verdict->sha256);
        $this->assertEquals(Verdict::PUP, $verdict->verdict);
    }
    
    public function testForFile_WithInvalidFile_ThrowsVaasClientException(): void
    {
        $this->expectException(VaasClientException::class);
        $this->expectExceptionMessage("File does not exist");
        
        $this->vaas->forFileAsync(__DIR__ . "/invalid")->await();
    }

    public function testForStream_WithCleanStream_GetsCleanResponse(): void
    {
        try {
            $stream = openFile(__DIR__ . "/composer.json", "r");
        } catch (FilesystemException $e) {
            $this->fail($e->getMessage());
        }
        $sha256 = hash_file("sha256", __DIR__ . "/composer.json");
        
        $verdict = $this->vaas->forStreamAsync($stream)->await();
        
        $this->assertEquals(Verdict::CLEAN, $verdict->verdict);
        $this->assertEqualsIgnoringCase($sha256, $verdict->sha256);
    }
    
    public function testForStream_WithMaliciousStream_GetsMaliciousResponse(): void
    {
        $file = file_get_contents(self::MALICIOUS_URL);
        file_put_contents(__DIR__ . "/eicar.com.txt", $file);
        
        try {
            $stream = openFile(__DIR__ . "/eicar.com.txt", "r");
        } catch (FilesystemException $e) {
            $this->fail($e->getMessage());
        }
        
        $verdict = $this->vaas->forStreamAsync($stream)->await();
        unlink(__DIR__ . "/eicar.com.txt");
        
        $this->assertEquals(Verdict::MALICIOUS, $verdict->verdict);
        $this->assertEqualsIgnoringCase(self::EICAR_HASH, $verdict->sha256);
    }
    
    // TODO: Check why the sha256 hash is different
    /**
     * @group exclude
     */
    public function testForStream_WithPupStream_GetsPupResponse(): void
    {
        $file = file_get_contents(self::PUP_URL);
        file_put_contents(__DIR__ . "/PotentiallyUnwanted.exe", $file);
        try {
            $stream = openFile(__DIR__ . "/PotentiallyUnwanted.exe", "r");
        } catch (FilesystemException $e) {
            $this->fail($e->getMessage());
        }
        
        $verdict = $this->vaas->forStreamAsync($stream)->await();
        unlink(__DIR__ . "/PotentiallyUnwanted.exe");

        $this->assertEqualsIgnoringCase(self::PUP_HASH, $verdict->sha256);
        $this->assertEquals(Verdict::PUP, $verdict->verdict);
    }
    
    public function testForStream_WithClosedStream_ThrowsVaasClientException(): void
    {
        $this->expectException(VaasClientException::class);
        $this->expectExceptionMessage("Stream is not readable");

        try {
            $stream = openFile(__DIR__ . "/composer.json", "r");
        } catch (FilesystemException $e) {
            $this->fail($e->getMessage());
        }
        $stream->close();
        
        $this->vaas->forStreamAsync($stream)->await();
    }
}