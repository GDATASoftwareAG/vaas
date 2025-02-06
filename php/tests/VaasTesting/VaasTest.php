<?php

namespace VaasTesting;

use Amp\File\FilesystemException;
use Dotenv\Dotenv;
use Monolog\Formatter\JsonFormatter;
use Monolog\Handler\StreamHandler;
use Monolog\Level;
use Monolog\Logger;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use Psr\Log\LoggerInterface;
use VaasSdk\Authentication\ClientCredentialsGrantAuthenticator;
use VaasSdk\Exceptions\InvalidSha256Exception;
use VaasSdk\Exceptions\VaasClientException;
use VaasSdk\Options\VaasOptions;
use VaasSdk\Sha256;
use VaasSdk\Vaas;
use VaasSdk\Verdict;
use function Amp\File\openFile;

final class VaasTest extends TestCase
{
    use ProphecyTrait;
    
    private Vaas $vaas;
    private LoggerInterface $logger;

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

        $this->logger = $this->_getDebugLogger();
        $this->vaas = $this->getVaas();
    }

    private function getVaas(bool $useCache = true, bool $useHashLookup = true): Vaas
    {
        $options = new VaasOptions(
            useHashLookup: $useHashLookup,
            useCache: $useCache,
            vaasUrl: $_ENV["VAAS_URL"] 
        );

        $authenticator = new ClientCredentialsGrantAuthenticator(
            $_ENV["CLIENT_ID"],
            $_ENV["CLIENT_SECRET"],
            $_ENV["TOKEN_URL"]
        );

        return Vaas::builder()
            ->withAuthenticator($authenticator)
            ->withOptions($options)
            ->withLogger($this->logger)
            ->build();
    }

    public function testForSha256_WithMaliciousSha256_GetsMaliciousResponse(): void
    {
        $verdict = $this->vaas->forSha256Async(Sha256::TryFromString(self::MALICIOUS_HASH)->await())->await();

        $this->logger->info('Test for malicious SHA256', [
            'expected' => Verdict::MALICIOUS,
            'actual' => $verdict->verdict,
            'sha256' => $verdict->sha256
        ]);

        $this->assertEquals(Verdict::MALICIOUS, $verdict->verdict);
        $this->assertEqualsIgnoringCase(self::MALICIOUS_HASH, $verdict->sha256);
    }

    public function testForSha256_WithPupSha256_GetsPupResponse(): void
    {
        $verdict = $this->vaas->forSha256Async(Sha256::TryFromString(self::PUP_HASH)->await())->await();

        $this->logger->info('Test for PUP SHA256', [
            'expected' => Verdict::PUP,
            'actual' => $verdict->verdict,
            'sha256' => $verdict->sha256
        ]);

        $this->assertEqualsIgnoringCase(self::PUP_HASH, $verdict->sha256);
        $this->assertEquals(Verdict::PUP, $verdict->verdict);
    }

    public function testForSha256_WithCleanSha256_GetsCleanResponse(): void
    {
        $verdict = $this->vaas->forSha256Async(Sha256::TryFromString(self::CLEAN_HASH)->await())->await();

        $this->logger->info('Test for clean SHA256', [
            'expected' => Verdict::CLEAN,
            'actual' => $verdict->verdict,
            'sha256' => $verdict->sha256
        ]);

        $this->assertEqualsIgnoringCase(self::CLEAN_HASH, $verdict->sha256);
        $this->assertEquals(Verdict::CLEAN, $verdict->verdict);
    }

    public function testForSha256_WithUnknownSha256_GetsUnknownResponse(): void
    {
        $vaas = $this->getVaas(false, false);

        $verdict = $vaas->forSha256Async(Sha256::TryFromString(self::UNKNOWN_HASH)->await())->await();

        $this->logger->info('Test for unknown SHA256', [
            'expected' => Verdict::UNKNOWN,
            'actual' => $verdict->verdict,
            'sha256' => $verdict->sha256
        ]);

        $this->assertEqualsIgnoringCase(self::UNKNOWN_HASH, $verdict->sha256);
        $this->assertEquals(Verdict::UNKNOWN, $verdict->verdict);
    }

    public function testForSha256_WithInvalidSha256_ThrowsInvalidSha256Exception(): void
    {
        $this->expectException(InvalidSha256Exception::class);
        $this->expectExceptionMessage("Invalid SHA256 hash");

        try {
            $this->vaas->forSha256Async(Sha256::TryFromString("invalid")->await())->await();
        } catch (InvalidSha256Exception $e) {
            $this->logger->error('Test for invalid SHA256', [
                'exception' => $e->getMessage()
            ]);
            throw $e;
        }
    }

    public function testForUrl_WithMaliciousUrl_GetsMaliciousResponse(): void
    {
        $verdict = $this->vaas->forUrlAsync(self::MALICIOUS_URL)->await();

        $this->logger->info('Test for malicious URL', [
            'expected' => Verdict::MALICIOUS,
            'actual' => $verdict->verdict,
            'url' => self::MALICIOUS_URL
        ]);

        $this->assertEquals(Verdict::MALICIOUS, $verdict->verdict);
    }

    public function testForUrl_WithPupUrl_GetsPupResponse(): void
    {
        $verdict = $this->vaas->forUrlAsync(self::PUP_URL)->await();

        $this->logger->info('Test for PUP URL', [
            'expected' => Verdict::PUP,
            'actual' => $verdict->verdict,
            'url' => self::PUP_URL
        ]);

        $this->assertEquals(Verdict::PUP, $verdict->verdict);
    }

    public function testForUrl_WithCleanUrl_GetsCleanResponse(): void
    {
        $verdict = $this->vaas->forUrlAsync(self::CLEAN_URL)->await();

        $this->logger->info('Test for clean URL', [
            'expected' => Verdict::CLEAN,
            'actual' => $verdict->verdict,
            'url' => self::CLEAN_URL
        ]);

        $this->assertEquals(Verdict::CLEAN, $verdict->verdict);
    }

    public function testForUrl_WithInvalidUrl_ThrowsVaasClientException(): void
    {
        $this->expectException(VaasClientException::class);
        $this->expectExceptionMessage("Invalid URI");

        $this->vaas->forUrlAsync("invalid")->await();
    }

    public function testForFile_WithCleanFile_GetsCleanResponse(): void
    {
        $verdict = $this->vaas->forFileAsync(__DIR__ . "/composer.json")->await();

        $this->logger->info('Test for clean file', [
            'expected' => Verdict::CLEAN,
            'actual' => $verdict->verdict,
            'file' => __DIR__ . "/composer.json"
        ]);

        $this->assertEquals(Verdict::CLEAN, $verdict->verdict);
    }

    public function testForFile_WithMaliciousFile_GetsMaliciousResponse(): void
    {
        $file = file_get_contents(self::MALICIOUS_URL);
        file_put_contents(__DIR__ . "/eicar.com.txt", $file);

        $verdict = $this->vaas->forFileAsync(__DIR__ . "/eicar.com.txt")->await();
        unlink(__DIR__ . "/eicar.com.txt");

        $this->logger->info('Test for malicious file', [
            'expected' => Verdict::MALICIOUS,
            'actual' => $verdict->verdict,
            'file' => __DIR__ . "/eicar.com.txt",
            'sha256' => $verdict->sha256
        ]);

        $this->assertEquals(Verdict::MALICIOUS, $verdict->verdict);
        $this->assertEqualsIgnoringCase(self::EICAR_HASH, $verdict->sha256);
    }

    public function testForFile_WithPupFile_GetsPupResponse(): void
    {
        $file = file_get_contents(self::PUP_URL);
        file_put_contents(__DIR__ . "/PotentiallyUnwanted.exe", $file);

        $verdict = $this->vaas->forFileAsync(__DIR__ . "/PotentiallyUnwanted.exe")->await();
        unlink(__DIR__ . "/PotentiallyUnwanted.exe");

        $this->logger->info('Test for PUP file', [
            'expected' => Verdict::PUP,
            'actual' => $verdict->verdict,
            'file' => __DIR__ . "/PotentiallyUnwanted.exe",
            'sha256' => $verdict->sha256
        ]);

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
        $fileSize = filesize(__DIR__ . "/composer.json");

        $verdict = $this->vaas->forStreamAsync($stream, $fileSize)->await();

        $this->logger->info('Test for clean stream', [
            'expected' => Verdict::CLEAN,
            'actual' => $verdict->verdict,
            'file' => __DIR__ . "/composer.json",
            'sha256' => $verdict->sha256
        ]);

        $this->assertEquals(Verdict::CLEAN, $verdict->verdict);
        $this->assertEqualsIgnoringCase($sha256, $verdict->sha256);
    }

    public function testForStream_WithMaliciousStream_GetsMaliciousResponse(): void
    {
        $file = file_get_contents(self::MALICIOUS_URL);
        file_put_contents(__DIR__ . "/eicar.com.txt", $file);
        $fileSize = filesize(__DIR__ . "/eicar.com.txt");

        try {
            $stream = openFile(__DIR__ . "/eicar.com.txt", "r");
        } catch (FilesystemException $e) {
            $this->fail($e->getMessage());
        }

        $verdict = $this->vaas->forStreamAsync($stream, $fileSize)->await();
        unlink(__DIR__ . "/eicar.com.txt");

        $this->logger->info('Test for malicious stream', [
            'expected' => Verdict::MALICIOUS,
            'actual' => $verdict->verdict,
            'file' => __DIR__ . "/eicar.com.txt",
            'sha256' => $verdict->sha256
        ]);

        $this->assertEquals(Verdict::MALICIOUS, $verdict->verdict);
        $this->assertEqualsIgnoringCase(self::EICAR_HASH, $verdict->sha256);
    }

    public function testForStream_WithPupStream_GetsPupResponse(): void
    {
        $file = file_get_contents(self::PUP_URL);
        file_put_contents(__DIR__ . "/PotentiallyUnwanted.exe", $file);
        try {
            $stream = openFile(__DIR__ . "/PotentiallyUnwanted.exe", "r");
        } catch (FilesystemException $e) {
            $this->fail($e->getMessage());
        }
        $fileSize = filesize(__DIR__ . "/PotentiallyUnwanted.exe");
        $verdict = $this->vaas->forStreamAsync($stream, $fileSize)->await();
        unlink(__DIR__ . "/PotentiallyUnwanted.exe");

        $this->logger->info('Test for PUP stream', [
            'expected' => Verdict::PUP,
            'actual' => $verdict->verdict,
            'file' => __DIR__ . "/PotentiallyUnwanted.exe",
            'sha256' => $verdict->sha256
        ]);

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
        $fileSize = filesize(__DIR__ . "/composer.json");

        $this->vaas->forStreamAsync($stream, $fileSize)->await();
    }

    private function _getDebugLogger(): LoggerInterface
    {
        global $argv;
        $monoLogger = new Logger("VaaS");

        if (in_array("--debug", $argv) === true) {
            $streamHandler = new StreamHandler(
                STDOUT,
                Level::Debug
            );
        } else {
            $streamHandler = new StreamHandler(
                STDOUT,
                Level::Info
            );
        }
        $streamHandler->setFormatter(new JsonFormatter());
        $monoLogger->pushHandler($streamHandler);
        return $monoLogger;
    }
}