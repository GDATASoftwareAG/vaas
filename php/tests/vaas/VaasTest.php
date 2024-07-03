<?php

namespace VaasTesting;

use Amp\ByteStream\Pipe;
use Amp\ByteStream\WritableBuffer;
use Amp\Http\Client\HttpClient;
use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\Request;
use JsonMapper_Exception;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use VaasSdk\Authentication\ClientCredentialsGrantAuthenticator;
use VaasSdk\Authentication\ResourceOwnerPasswordGrantAuthenticator;
use VaasSdk\Exceptions\TimeoutException;
use VaasSdk\Exceptions\UploadFailedException;
use VaasSdk\Exceptions\VaasAuthenticationException;
use VaasSdk\Exceptions\VaasClientException;
use VaasSdk\Exceptions\VaasServerException;
use VaasSdk\Vaas;
use Dotenv\Dotenv;
use Exception;
use Monolog\Formatter\JsonFormatter;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Psr\Log\LoggerInterface;
use Monolog\Logger;
use Ramsey\Uuid\Generator\RandomBytesGenerator;
use Ramsey\Uuid\Rfc4122\UuidV4;
use Revolt\EventLoop;
use VaasSdk\Exceptions\VaasInvalidStateException;
use VaasSdk\Message\Verdict;
use VaasSdk\Sha256;
use VaasSdk\VaasOptions;
use WebSocket\BadOpcodeException;

use function Amp\ByteStream\Internal\tryToCreateReadableStreamFromResource;

final class VaasTest extends TestCase
{
    use ProphecyTrait;

    const MALICIOUS_HASH = "ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2";
    const MALICIOUS_URL = "https://secure.eicar.org/eicar.com.txt";
    private HttpClient $httpClient;

    public function setUp(): void
    {
        $httpClientBuilder = (new HttpClientBuilder())
            ->skipAutomaticCompression()
            ->skipDefaultAcceptHeader();
        $this->httpClient = $httpClientBuilder->build();

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
        if (getenv("VAAS_USER_NAME") !== false) {
            $_ENV["VAAS_USER_NAME"] = getenv("VAAS_USER_NAME");
        }
        if (getenv("VAAS_PASSWORD") !== false) {
            $_ENV["VAAS_PASSWORD"] = getenv("VAAS_PASSWORD");
        }
        if (getenv("VAAS_CLIENT_ID") !== false) {
            $_ENV["VAAS_CLIENT_ID"] = getenv("VAAS_CLIENT_ID");
        }
    }

    private function _getVaas(bool $useCache = false, bool $useHashLookup = true, LoggerInterface $logger = null): Vaas
    {
        return new Vaas($_ENV["VAAS_URL"], $logger != null ? $logger : $this->_getDebugLogger(), new VaasOptions($useCache, $useHashLookup));
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

    private function getClientCredentialsGrantAuthenticator(): ClientCredentialsGrantAuthenticator
    {
        return new ClientCredentialsGrantAuthenticator(
            $_ENV['CLIENT_ID'],
            $_ENV['CLIENT_SECRET'],
            $_ENV["TOKEN_URL"]
        );
    }

    private function getResourceOwnerPasswordAuthenticator(): ResourceOwnerPasswordGrantAuthenticator
    {
        return new ResourceOwnerPasswordGrantAuthenticator(
            $_ENV['VAAS_CLIENT_ID'],
            $_ENV['VAAS_USER_NAME'],
            $_ENV["VAAS_PASSWORD"],
            $_ENV["TOKEN_URL"]
        );
    }

    public function testForSha256MaliciousSha256_WithResourceOwnerPasswordAuthenticator_GetsMaliciousResponse(): void
    {
        $uuid = $this->getUuid();

        $vaas = $this->_getVaas();
        $vaas->Connect($this->getResourceOwnerPasswordAuthenticator()->getToken());
        $verdict = $vaas->ForSha256(self::MALICIOUS_HASH, $uuid);

        $this->assertEquals(Verdict::MALICIOUS, $verdict->Verdict);
        $this->assertEquals($uuid, $verdict->Guid);
        $this->assertEqualsIgnoringCase(self::MALICIOUS_HASH, $verdict->Sha256);
    }

    public function testForConnectingWithInvalidToken_ThrowsVaasAccessDeniedException()
    {
        $this->expectException(VaasAuthenticationException::class);
        $vaas = $this->_getVaas();
        $vaas->Connect("invalid");
    }

    public function testForRequestHashBeforeConnec_ThrowsVaasInvalidStateException()
    {
        $this->expectException(VaasInvalidStateException::class);
        $vaas = $this->_getVaas();
        $vaas->ForSha256(self::MALICIOUS_HASH, "someuuid");
    }

    public function testForSha256MaliciousSha256_GetsMaliciousResponse(): void
    {
        $uuid = $this->getUuid();

        $vaas = $this->_getVaas();
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());
        $verdict = $vaas->ForSha256(self::MALICIOUS_HASH, $uuid);

        $this->assertEquals(Verdict::MALICIOUS, $verdict->Verdict);
        $this->assertEquals($uuid, $verdict->Guid);
        $this->assertEqualsIgnoringCase(self::MALICIOUS_HASH, $verdict->Sha256);
    }

    public function testForSha256MaliciousSha256WithFlag_BothFlagsFalse_GetsMaliciousResponse(): void
    {
        $uuid = $this->getUuid();

        $vaas = $this->_getVaas();
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());
        $verdict = $vaas->ForSha256(self::MALICIOUS_HASH, $uuid);

        $this->assertEquals(Verdict::MALICIOUS, $verdict->Verdict);
        $this->assertEquals($uuid, $verdict->Guid);
        $this->assertEqualsIgnoringCase(self::MALICIOUS_HASH, $verdict->Sha256);
    }

    public function testForSha256CleanSha256_GetsCleanResponse(): void
    {
        $uuid = $this->getUuid();
        $cleanSha256 = "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e";

        $vaas = $this->_getVaas();
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());
        $verdict = $vaas->ForSha256($cleanSha256, $uuid);

        $this->assertEquals(Verdict::CLEAN, $verdict->Verdict);
        $this->assertEquals($uuid, $verdict->Guid);
        $this->assertEqualsIgnoringCase($cleanSha256, $verdict->Sha256);
    }

    public function testForSha256AmtsoPupSample_GetsPupResponse(): void
    {
        $uuid = $this->getUuid();
        $pupSha256 = "d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad";
        $vaas = $this->_getVaas();
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());

        $verdict = $vaas->ForSha256($pupSha256, $uuid);

        $this->assertEquals(Verdict::PUP, $verdict->Verdict);
        $this->assertEquals($uuid, $verdict->Guid);
        $this->assertEqualsIgnoringCase($pupSha256, $verdict->Sha256);
    }

    public function testForMultipleHashes_GetsResponse(): void
    {
        $uuid1 = $this->getUuid();
        $uuid2 = $this->getUuid();
        $uuid3 = $this->getUuid();
        $cleanHash1 = "ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2";
        $cleanHash2 = "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e";
        $cleanHash3 = "1f72c1111111111111f912e40b7323a0192a300b376186c10f6803dc5efe28df";

        $vaas = $this->_getVaas();
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());

        $verdict1 = $vaas->ForSha256($cleanHash1, $uuid1);
        $verdict2 = $vaas->ForSha256($cleanHash2, $uuid2);
        $verdict3 = $vaas->ForSha256($cleanHash3, $uuid3);

        $this->assertEquals(Verdict::MALICIOUS, $verdict1->Verdict);
        $this->assertEquals($uuid1, $verdict1->Guid);
        $this->assertEqualsIgnoringCase($cleanHash1, $verdict1->Sha256);
        $this->assertEquals(Verdict::CLEAN, $verdict2->Verdict);
        $this->assertEquals($uuid2, $verdict2->Guid);
        $this->assertEqualsIgnoringCase($cleanHash2, $verdict2->Sha256);
        $this->assertEquals(Verdict::UNKNOWN, $verdict3->Verdict);
        $this->assertEquals($uuid3, $verdict3->Guid);
        $this->assertEqualsIgnoringCase($cleanHash3, $verdict3->Sha256);
    }

    public function testForSha256UnknownSha256_GetsUnknownResponse(): void
    {
        $uuid = $this->getUuid();
        $unkownHash = "00000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fbbb";

        $vaas = $this->_getVaas();
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());
        $verdict = $vaas->ForSha256($unkownHash, $uuid);

        $this->assertEquals(Verdict::UNKNOWN, $verdict->Verdict);
        $this->assertEquals($uuid, $verdict->Guid);
        $this->assertEqualsIgnoringCase($unkownHash, $verdict->Sha256);
    }

    public function testForMultipleUnknownFiles_GetsUnknownResponses(): void
    {
        $uuid1 = $this->getUuid();
        $uuid2 = $this->getUuid();
        $uuid3 = $this->getUuid();
        $unknownHash1 = "110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8";
        $unknownHash2 = "11000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c";
        $unknownHash3 = "11000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fd1a";

        $vaas = $this->_getVaas();
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());

        $verdict1 = $vaas->ForSha256($unknownHash1, $uuid1);
        $verdict2 = $vaas->ForSha256($unknownHash2, $uuid2);
        $verdict3 = $vaas->ForSha256($unknownHash3, $uuid3);

        $this->assertEquals(Verdict::UNKNOWN, $verdict1->Verdict);
        $this->assertEquals($uuid1, $verdict1->Guid);
        $this->assertEqualsIgnoringCase($unknownHash1, $verdict1->Sha256);
        $this->assertEquals(Verdict::UNKNOWN, $verdict2->Verdict);
        $this->assertEquals($uuid2, $verdict2->Guid);
        $this->assertEqualsIgnoringCase($unknownHash2, $verdict2->Sha256);
        $this->assertEquals(Verdict::UNKNOWN, $verdict3->Verdict);
        $this->assertEquals($uuid3, $verdict3->Guid);
        $this->assertEqualsIgnoringCase($unknownHash3, $verdict3->Sha256);
    }

    public function testForFileWithFlagsCleanFile_GetsCleanResponse(): void
    {
        $uuid = $this->getUuid();

        $cleanFile = pack("nvc*", 0x65, 0x0a, 0x67, 0x0a, 0x65, 0x0a, 0x62, 0x0a);
        $tmp = tmpfile();
        fwrite($tmp, $cleanFile);
        fseek($tmp, 0);
        $sha256 = Sha256::TryFromFile(stream_get_meta_data($tmp)['uri']);

        $vaas = $this->_getVaas();
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());
        $verdict = $vaas->ForFile(stream_get_meta_data($tmp)['uri'], true, $uuid);

        $this->assertEquals(Verdict::CLEAN, $verdict->Verdict);
        $this->assertEquals($uuid, $verdict->Guid);
        $this->assertEqualsIgnoringCase($sha256, $verdict->Sha256);

        fclose($tmp);
    }

    public function testForFileCleanFile_GetsCleanResponse(): void
    {
        $uuid = $this->getUuid();

        $cleanFile = pack("nvc*", 0x65, 0x0a, 0x67, 0x0a, 0x65, 0x0a, 0x62, 0x0a);
        $tmp = tmpfile();
        fwrite($tmp, $cleanFile);
        fseek($tmp, 0);
        $sha256 = Sha256::TryFromFile(stream_get_meta_data($tmp)['uri']);

        $vaas = $this->_getVaas();
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());
        $verdict = $vaas->ForFile(stream_get_meta_data($tmp)['uri'], true, $uuid);

        $this->assertEquals(Verdict::CLEAN, $verdict->Verdict);
        $this->assertEquals($uuid, $verdict->Guid);
        $this->assertEqualsIgnoringCase($sha256, $verdict->Sha256);

        fclose($tmp);
    }

    public function testForFileMaliciousFile_GetsMaliciousResponse(): void
    {
        $uuid = $this->getUuid();

        $tmp = tmpfile();
        fwrite($tmp, "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*");
        fseek($tmp, 0);
        $sha256 = Sha256::TryFromFile(stream_get_meta_data($tmp)['uri']);

        $vaas = $this->_getVaas();
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());
        $verdict = $vaas->ForFile(stream_get_meta_data($tmp)['uri'], true, $uuid);

        $this->assertEquals(Verdict::MALICIOUS, $verdict->Verdict);
        $this->assertEquals($uuid, $verdict->Guid);
        $this->assertEqualsIgnoringCase($sha256, $verdict->Sha256);

        fclose($tmp);
    }

    public function testForFileRandomFile_GetsCleanResponseAfterUpload(): void
    {
        $uuid = $this->getUuid();

        $tmp = tmpfile();
        fwrite($tmp, $uuid);
        fseek($tmp, 0);
        $sha256 = Sha256::TryFromFile(stream_get_meta_data($tmp)['uri']);

        $vaas = $this->_getVaas();
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());
        $verdict = $vaas->ForFile(stream_get_meta_data($tmp)['uri'], true, $uuid);

        $this->assertEquals(Verdict::CLEAN, $verdict->Verdict);
        $this->assertEquals($uuid, $verdict->Guid);
        $this->assertEquals($sha256, $verdict->Sha256);

        fclose($tmp);
    }

    public function testForEmptyFile_GetsCleanResponse(): void
    {
        $uuid = $this->getUuid();

        $tmp = tmpfile();
        fwrite($tmp, "");
        fseek($tmp, 0);
        $sha256 = Sha256::TryFromFile(stream_get_meta_data($tmp)['uri']);

        $vaas = $this->_getVaas();
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());
        $verdict = $vaas->ForFile(stream_get_meta_data($tmp)['uri'], true, $uuid);

        $this->assertEquals(Verdict::CLEAN, $verdict->Verdict);
        $this->assertEquals($uuid, $verdict->Guid);
        $this->assertEquals($sha256, $verdict->Sha256);

        fclose($tmp);
    }

    public function testForUrlWithFlagsMaliciousUrl_GetsMaliciousResponse(): void
    {
        $uuid = $this->getUuid();

        $vaas = $this->_getVaas();
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());
        $verdict = $vaas->ForUrl(self::MALICIOUS_URL, $uuid);

        $this->assertEquals(Verdict::MALICIOUS, $verdict->Verdict);
        $this->assertEquals($uuid, $verdict->Guid);
    }

    public function testForUrlMaliciousUrl_GetsMaliciousResponse(): void
    {
        $uuid = $this->getUuid();

        $vaas = $this->_getVaas();
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());
        $verdict = $vaas->ForUrl(self::MALICIOUS_URL, $uuid);

        $this->assertEquals(Verdict::MALICIOUS, $verdict->Verdict);
        $this->assertEquals($uuid, $verdict->Guid);
    }

    public function testForUrlCleanUrl_GetsCleanResponse(): void
    {
        $uuid = $this->getUuid();

        $vaas = $this->_getVaas();
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());
        $verdict = $vaas->ForUrl("https://www.gdatasoftware.com/oem/verdict-as-a-service", $uuid);

        $this->assertEquals(Verdict::CLEAN, $verdict->Verdict);
        $this->assertEquals($uuid, $verdict->Guid);
    }

    /**
     * @outputBuffering disabled
     */
    private function getUuid(): string
    {
        $uuid = UuidV4::getFactory()->uuid4()->toString();
        echo "Generated UUID: $uuid \n";
        return $uuid;
    }

    /**
     * @throws VaasAuthenticationException
     * @throws TimeoutException
     */
    public function testForUrl_WithInvalidUrl_ThrowsVaasClientException()
    {
        $vaas = $this->_getVaas();
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Url is not valid");
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());

        $invalidUrl = "https://";
        $verdict = $vaas->ForUrl($invalidUrl);
        $this->_getDebugLogger()->info("Verdict for URL " . $invalidUrl . " is " . $verdict->Verdict);
    }

    /**
     * @throws VaasAuthenticationException
     * @throws TimeoutException
     */
    public function testForUrl_WithNull_ThrowsVaasClientException()
    {
        $vaas = $this->_getVaas();
        $this->expectException(\InvalidArgumentException::class);
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());

        $invalidUrl = null;
        $verdict = $vaas->ForUrl($invalidUrl);
        $this->_getDebugLogger()->info("Verdict for URL " . $invalidUrl . " is " . $verdict->Verdict);
    }

    /**
     * @throws VaasAuthenticationException
     * @throws TimeoutException
     */
    public function testForUrl_WithStatus4xx_ThrowsVaasClientException()
    {
        $vaas = $this->_getVaas();
        $this->expectException(VaasClientException::class);
        $this->expectExceptionMessage("Call failed with status code 404 (Not Found): GET https://upload.production.vaas.gdatasecurity.de/nocontenthere");
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());

        $invalidUrl = "https://upload.production.vaas.gdatasecurity.de/nocontenthere";
        $verdict = $vaas->ForUrl($invalidUrl);
        $this->_getDebugLogger()->info("Verdict for URL " . $invalidUrl . " is " . $verdict->Verdict);
    }

    public function testForStreamWithFlags_WithEicarString_ReturnsMalicious()
    {
        $vaas = $this->_getVaas();
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*";
        $resourceStream = tryToCreateReadableStreamFromResource(fopen(sprintf('data://text/plain,%s', $eicar), 'r'));

        $verdict = $vaas->ForStream($resourceStream, strlen($eicar));

        $this->assertEquals(Verdict::MALICIOUS, $verdict->Verdict);
    }

    /**
     * @throws JsonMapper_Exception
     * @throws VaasClientException
     * @throws VaasServerException
     * @throws UploadFailedException
     * @throws TimeoutException
     * @throws BadOpcodeException
     * @throws GuzzleException
     * @throws VaasAuthenticationException
     * @throws VaasInvalidStateException
     */
    public function testForStream_WithEicarString_ReturnsMalicious()
    {
        $vaas = $this->_getVaas(false, false);
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());
        $eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

        $resourceStream = tryToCreateReadableStreamFromResource(fopen(sprintf('data://text/plain,%s', $eicar), 'r'));

        $verdict = $vaas->ForStream($resourceStream, strlen($eicar));

        $this->assertEquals(Verdict::MALICIOUS, $verdict->Verdict);
    }

    /**
     * @throws JsonMapper_Exception
     * @throws VaasClientException
     * @throws VaasServerException
     * @throws TimeoutException
     * @throws UploadFailedException
     * @throws GuzzleException
     * @throws BadOpcodeException
     * @throws VaasInvalidStateException
     * @throws VaasAuthenticationException
     */
    public function testForStream_WithCleanString_ReturnsClean()
    {
        $vaas = $this->_getVaas();
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());
        $clean = str_replace("\0", "", (new RandomBytesGenerator())->generate(64));
        $resourceStream = tryToCreateReadableStreamFromResource(fopen(sprintf('data://text/plain,%s', $clean), 'r'));

        $verdict = $vaas->ForStream($resourceStream, strlen($clean));

        $this->assertEquals(Verdict::CLEAN, $verdict->Verdict);
    }

    /**
     * @throws GuzzleException
     * @throws JsonMapper_Exception
     * * @throws VaasClientException
     * * @throws VaasServerException
     * * @throws TimeoutException
     * * @throws UploadFailedException
     * * @throws GuzzleException
     * * @throws BadOpcodeException
     * * @throws VaasInvalidStateException
     * * @throws VaasAuthenticationException
     */
    public function testForStream_WithCleanUrlContentAsStream_ReturnsClean()
    {
        $url = "https://raw.githubusercontent.com/GDATASoftwareAG/vaas/main/Readme.md";
        $request = new Request($url);
        try {
            $response = $this->httpClient->request($request);
            if ($response->getStatus() != 200) {
                throw new Exception($response->getReason(), $response->getStatus());
            }
        } catch(Exception $e) {
            echo $e->getMessage();
        }
        $body = $response->getBody();
        $size = $response->getHeader("Content-Length");

        $vaas = $this->_getVaas();
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());
        $verdict = $vaas->ForStream($body, $size);
        $this->assertEquals(Verdict::CLEAN, $verdict->Verdict);
    }

    /**
     * @throws GuzzleException
     * @throws JsonMapper_Exception
     * * @throws VaasClientException
     * * @throws VaasServerException
     * * @throws TimeoutException
     * * @throws UploadFailedException
     * * @throws GuzzleException
     * * @throws BadOpcodeException
     * * @throws VaasInvalidStateException
     * * @throws VaasAuthenticationException
     */
    public function testForStream_WithCleanDelayedfor11Seconds_ReturnsClean()
    {
        $monoLogger = new Logger("VaaS");
        $testHandler = new TestHandler(Level::Debug);
        $monoLogger->pushHandler($testHandler);

        $vaas = $this->_getVaas(false, false, $monoLogger);
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());

        $randomString = $this->random_strings(11000);

        $stream = new Pipe(11000);
        $writeTimer = EventLoop::repeat(0.001, function () use ($stream, &$randomString) {
            if ($randomString === "") {
                $stream->getSink()->end();
                return;
            }
            $data = substr($randomString, 0, 1);
            $randomString = substr($randomString, 1);
            $stream->getSink()->write($data);
        });

        try {
            $verdict = $vaas->ForStream($stream->getSource(), 11000);
        } catch(Exception $e) {
            throw $e;
        } finally {
            EventLoop::cancel($writeTimer);
        }

        $pingCount = 0;
        foreach($testHandler->getRecords() as $record) {
            if (stristr($record->message, "pinging") !== false)
                $pingCount++;
        };
        $this->assertEquals(2, $pingCount);
        $this->assertEquals(Verdict::CLEAN, $verdict->Verdict);
    }

    /**
     * @throws GuzzleException
     * @throws JsonMapper_Exception
     * * @throws VaasClientException
     * * @throws VaasServerException
     * * @throws TimeoutException
     * * @throws UploadFailedException
     * * @throws GuzzleException
     * * @throws BadOpcodeException
     * * @throws VaasInvalidStateException
     * * @throws VaasAuthenticationException
     */
    public function testForStream_WithEicarUrlContentAsStream_ReturnsMalicious()
    {
        $request = new Request(self::MALICIOUS_URL);
        try {
            $response = $this->httpClient->request($request);
            if ($response->getStatus() != 200) {
                throw new Exception($response->getReason(), $response->getStatus());
            }
        } catch(Exception $e) {
            echo $e->getMessage();
        }
        $body = $response->getBody();
        $size = $response->getHeader("Content-Length");

        $vaas = $this->_getVaas();
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());
        $verdict = $vaas->ForStream($body, $size);

        $this->assertEquals(Verdict::MALICIOUS, $verdict->Verdict);
    }

    public function testForStream_WithEicarUrlContentAsStream_ReturnsMaliciousWithDetectionAndMimeType()
    {
        $request = new Request(self::MALICIOUS_URL);
        try {
            $response = $this->httpClient->request($request);
            if ($response->getStatus() != 200) {
                throw new Exception($response->getReason(), $response->getStatus());
            }
        } catch(Exception $e) {
            echo $e->getMessage();
        }
        $body = $response->getBody();
        $size = $response->getHeader("Content-Length");

        $vaas = $this->_getVaas();
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());
        $verdict = $vaas->ForStream($body, $size);

        $this->assertEquals(Verdict::MALICIOUS, $verdict->Verdict);
        $this->assertEquals("text/plain", $verdict->MimeType);
        $this->assertNotEmpty($verdict->Detection);
    }

    static function random_strings($length_of_string) {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $characters_length = strlen($characters);
        $random_string = '';

        // Generate random characters until the string reaches desired length
        for ($i = 0; $i < $length_of_string; $i++) {
            $random_index = random_int(0, $characters_length - 1);
            $random_string .= $characters[$random_index];
        }

        return $random_string;
    }
}
