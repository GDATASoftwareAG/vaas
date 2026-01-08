<?php

namespace VaasTesting;

use Amp\File\Driver\BlockingFilesystemDriver;
use Amp\File\File;
use Amp\File\FilesystemDriver;
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
use VaasSdk\Options\ForFileOptions;
use VaasSdk\Options\ForSha256Options;
use VaasSdk\Options\VaasOptions;
use VaasSdk\Sha256;
use VaasSdk\Vaas;
use VaasSdk\Verdict;
use function Amp\File\filesystem;
use function Amp\File\openFile;

final class VaasTest extends TestCase
{
    use ProphecyTrait;
    
    private Vaas $vaas;
    private LoggerInterface $logger;

    const MALICIOUS_HASH = "ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2";
    const EICAR_HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    const PUP_HASH = "d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad";
    const CLEAN_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const UNKNOWN_HASH = "23b85b080bda43cd0dd80f0386d66b8a5f3ca647441df0306d8c74ef035cfe93";
    
    const MALICIOUS_URL = "https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/eicar.com.txt";
    const PUP_URL = "https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/PotentiallyUnwanted.exe";
    const CLEAN_URL = "https://s3-eu-central-2.ionoscloud.com/test-samples-vaas/clean.txt";

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

    private function getVaas(bool $useCache = false, bool $useHashLookup = true): Vaas
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
        // You need to scan the verdict from the file first to have the hash in the cache because the hash-lookup do not know the PUP hash
        $file = file_get_contents(self::PUP_URL);
        file_put_contents(__DIR__ . "/PotentiallyUnwanted.exe", $file);
        $verdictFromFileScan = $this->vaas->forFileAsync(__DIR__ . "/PotentiallyUnwanted.exe")->await();
        unlink(__DIR__ . "/PotentiallyUnwanted.exe");
        $options = new ForSha256Options(useCache: true, useHashLookup: true);
        
        // Act
        $verdict = $this->vaas->forSha256Async(Sha256::TryFromString(self::PUP_HASH)->await(), $options)->await();

        $this->logger->info('Test for PUP SHA256', [
            'expected' => Verdict::PUP,
            'actual' => $verdict->verdict,
            'sha256' => $verdict->sha256
        ]);

        $this->assertEqualsIgnoringCase(self::PUP_HASH, $verdict->sha256);
        $this->assertEquals(Verdict::PUP, $verdict->verdict);
        $this->assertEquals($verdictFromFileScan->verdict, $verdict->verdict);
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

	public function testForFile_WithCustomFilesystemDriver_UtilizesDriver(): void
	{
		$file = file_get_contents(self::PUP_URL);
		file_put_contents(__DIR__ . "/PotentiallyUnwantedCustomDriver.exe", $file);
		$customDriverCalled = false;
		$customDriver = new class(
			function () use (&$customDriverCalled) {
				$customDriverCalled = true;
			}
		) implements FileSystemDriver {
			private $callback;

			public function __construct(callable $callback)
			{
				$this->callback = $callback;
			}

			public function openFile(string $path, string $mode): File
			{
				($this->callback)();
				return filesystem(new BlockingFilesystemDriver())->openFile($path, $mode);
			}

			public function getStatus(string $path): ?array
			{
				return filesystem(new BlockingFilesystemDriver())->getStatus($path);
			}

			public function getLinkStatus(string $path): ?array
			{
				throw new BadMethodCallException('Not implemented');
			}

			public function createSymlink(string $target, string $link): void
			{
				throw new BadMethodCallException('Not implemented');
			}

			public function createHardlink(string $target, string $link): void
			{
				throw new BadMethodCallException('Not implemented');
			}

			public function resolveSymlink(string $target): string
			{
				throw new BadMethodCallException('Not implemented');
			}

			public function move(string $from, string $to): void
			{
				throw new BadMethodCallException('Not implemented');
			}

			public function deleteFile(string $path): void
			{
				throw new BadMethodCallException('Not implemented');
			}

			public function createDirectory(string $path, int $mode = 0777): void
			{
				throw new BadMethodCallException('Not implemented');
			}

			public function createDirectoryRecursively(string $path, int $mode = 0777): void
			{
				throw new BadMethodCallException('Not implemented');
			}

			public function deleteDirectory(string $path): void
			{
				throw new BadMethodCallException('Not implemented');
			}

			public function listFiles(string $path): array
			{
				throw new BadMethodCallException('Not implemented');
			}

			public function changePermissions(string $path, int $mode): void
			{
				throw new BadMethodCallException('Not implemented');
			}

			public function changeOwner(string $path, ?int $uid, ?int $gid): void
			{
				throw new BadMethodCallException('Not implemented');
			}

			public function touch(string $path, ?int $modificationTime, ?int $accessTime): void
			{
				throw new BadMethodCallException('Not implemented');
			}

			public function read(string $path): string
			{
				throw new BadMethodCallException('Not implemented');
			}

			public function write(string $path, string $contents): void
			{
				throw new BadMethodCallException('Not implemented');
			}
		};

		$verdict = $this->vaas->forFileAsync(__DIR__ . "/PotentiallyUnwantedCustomDriver.exe", new ForFileOptions(false, false, ForFileOptions::DEFAULT_TIMEOUT, $customDriver))->await();

		unlink(__DIR__ . "/PotentiallyUnwantedCustomDriver.exe");
		$this->assertEquals(Verdict::PUP, $verdict->verdict);
		$this->assertTrue($customDriverCalled, "custom driver not called");
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