<?php

namespace VaasTesting;

require_once __DIR__ . "/vendor/autoload.php";

use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use VaasSdk\ClientCredentialsGrantAuthenticator;
use VaasSdk\Exceptions\VaasAuthenticationException;
use VaasSdk\Vaas;
use Dotenv\Dotenv;
use Monolog\Formatter\JsonFormatter;
use Monolog\Handler\StreamHandler;
use Psr\Log\LoggerInterface;
use Monolog\Logger;
use Ramsey\Uuid\Rfc4122\UuidV4;
use VaasSdk\Exceptions\VaasInvalidStateException;
use VaasSdk\Message\Verdict;
use VaasSdk\Sha256;

use function PHPUnit\Framework\assertEquals;

final class VaasTest extends TestCase
{
    use ProphecyTrait;

    const MALICIOUS_HASH = "000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8";
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

    private function _getDebugLogger(): LoggerInterface
    {
        global $argv;
        $monoLogger = new Logger("VaaS");

        if (in_array("--debug", $argv) === true) {
            $streamHandler = new StreamHandler(
                STDOUT,
                Logger::DEBUG
            );
        } else {
            $streamHandler = new StreamHandler(
                STDOUT,
                Logger::INFO
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

    public function testForConnectingWithInvalidToken_ThrowsVaasAccessDeniedException()
    {
        $this->expectException(VaasAuthenticationException::class);
        $vaas = new Vaas($_ENV["VAAS_URL"], $this->_getDebugLogger());
        $vaas->Connect("invalid");
    }

    public function testForRequestHashBeforeConnec_ThrowsVaasInvalidStateException()
    {
        $this->expectException(VaasInvalidStateException::class);
        $vaas = new Vaas($_ENV["VAAS_URL"], $this->_getDebugLogger());
        $vaas->ForSha256(self::MALICIOUS_HASH, "someuuid");
    }

    public function testForSha256MaliciousSha256_GetsMaliciousResponse(): void
    {
        $uuid = $this->getUuid();

        $vaas = new Vaas($_ENV["VAAS_URL"], $this->_getDebugLogger());
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());
        $verdict = $vaas->ForSha256(self::MALICIOUS_HASH, $uuid);

        $this->assertEquals(Verdict::MALICIOUS, $verdict->Verdict);
        $this->assertEquals($uuid, $verdict->Guid);
        $this->assertEqualsIgnoringCase(self::MALICIOUS_HASH, $verdict->Sha256);
    }

    public function testForMultipleMaliciousSha256_GetsMaliciousResponses(): void
    {
        $vaas = new Vaas($_ENV["VAAS_URL"], $this->_getDebugLogger());
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());

        $uuid1 = $this->getUuid();
        $sha256_1 = "000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8";
        $uuid2 = $this->getUuid();
        $sha256_2 = "00000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c";
        $uuid3 = $this->getUuid();
        $sha256_3 = "00000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fd1a";

        $verdict1 = $vaas->ForSha256($sha256_1, $uuid1);
        $verdict2 = $vaas->ForSha256($sha256_2, $uuid2);
        $verdict3 = $vaas->ForSha256($sha256_3, $uuid3);

        $this->assertEquals(Verdict::MALICIOUS, $verdict1->Verdict);
        $this->assertEquals($uuid1, $verdict1->Guid);
        $this->assertEqualsIgnoringCase($sha256_1, $verdict1->Sha256);

        $this->assertEquals(Verdict::MALICIOUS, $verdict2->Verdict);
        $this->assertEquals($uuid2, $verdict2->Guid);
        $this->assertEqualsIgnoringCase($sha256_2, $verdict2->Sha256);

        $this->assertEquals(Verdict::MALICIOUS, $verdict3->Verdict);
        $this->assertEquals($uuid3, $verdict3->Guid);
        $this->assertEqualsIgnoringCase($sha256_3, $verdict3->Sha256);
    }

    public function testForSha256CleanSha256_GetsCleanResponse(): void
    {
        $uuid = $this->getUuid();
        $cleanSha256 = "3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C";

        $vaas = new Vaas($_ENV["VAAS_URL"], $this->_getDebugLogger());
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
        $vaas = new Vaas($_ENV["VAAS_URL"], $this->_getDebugLogger());
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());

        $verdict = $vaas->ForSha256($pupSha256, $uuid);

        $this->assertEquals(Verdict::PUP, $verdict->Verdict);
        $this->assertEquals($uuid, $verdict->Guid);
        $this->assertEqualsIgnoringCase($pupSha256, $verdict->Sha256);
    }

    public function testForMultipleCleanFiles_GetsCleanResponses(): void
    {
        $uuid1 = $this->getUuid();
        $uuid2 = $this->getUuid();
        $uuid3 = $this->getUuid();
        $cleanHash1 = "3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C";
        $cleanHash2 = "1AFAFE9157FF5670BBEC8CE622F45D1CE51B3EE77B7348D3A237E232F06C5391";
        $cleanHash3 = "4447FAACEFABA8F040822101E2A4103031660DE9139E70ECFF9AA3A89455A783";

        $vaas = new Vaas($_ENV["VAAS_URL"], $this->_getDebugLogger());
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());

        $verdict1 = $vaas->ForSha256($cleanHash1, $uuid1);
        $verdict2 = $vaas->ForSha256($cleanHash2, $uuid2);
        $verdict3 = $vaas->ForSha256($cleanHash3, $uuid3);

        $this->assertEquals(Verdict::CLEAN, $verdict1->Verdict);
        $this->assertEquals($uuid1, $verdict1->Guid);
        $this->assertEqualsIgnoringCase($cleanHash1, $verdict1->Sha256);
        $this->assertEquals(Verdict::CLEAN, $verdict2->Verdict);
        $this->assertEquals($uuid2, $verdict2->Guid);
        $this->assertEqualsIgnoringCase($cleanHash2, $verdict2->Sha256);
        $this->assertEquals(Verdict::CLEAN, $verdict3->Verdict);
        $this->assertEquals($uuid3, $verdict3->Guid);
        $this->assertEqualsIgnoringCase($cleanHash3, $verdict3->Sha256);
    }

    public function testForSha256UnknownSha256_GetsUnknownResponse(): void
    {
        $uuid = $this->getUuid();
        $unkownHash = "00000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fbbb";

        $vaas = new Vaas($_ENV["VAAS_URL"], $this->_getDebugLogger());
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

        $vaas = new Vaas($_ENV["VAAS_URL"], $this->_getDebugLogger());
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

    public function testForFileCleanFile_GetsCleanResponse(): void
    {
        $uuid = $this->getUuid();

        $cleanFile = pack("nvc*", 0x65, 0x0a, 0x67, 0x0a, 0x65, 0x0a, 0x62, 0x0a);
        $tmp = tmpfile();
        fwrite($tmp, $cleanFile);
        fseek($tmp, 0);
        $sha256 = Sha256::TryFromFile(stream_get_meta_data($tmp)['uri']);

        $vaas = new Vaas($_ENV["VAAS_URL"], $this->_getDebugLogger());
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

        $vaas = new Vaas($_ENV["VAAS_URL"], $this->_getDebugLogger());
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

        $vaas = new Vaas($_ENV["VAAS_URL"], $this->_getDebugLogger());
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

        $vaas = new Vaas($_ENV["VAAS_URL"], $this->_getDebugLogger());
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());
        $verdict = $vaas->ForFile(stream_get_meta_data($tmp)['uri'], true, $uuid);

        $this->assertEquals(Verdict::CLEAN, $verdict->Verdict);
        $this->assertEquals($uuid, $verdict->Guid);
        $this->assertEquals($sha256, $verdict->Sha256);

        fclose($tmp);
    }

    public function testForUrlMaliciousUrl_GetsMaliciousResponse(): void
    {
        $uuid = $this->getUuid();

        $vaas = new Vaas($_ENV["VAAS_URL"], $this->_getDebugLogger());
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());
        $verdict = $vaas->ForUrl(self::MALICIOUS_URL, $uuid);

        $this->assertEquals(Verdict::MALICIOUS, $verdict->Verdict);
        $this->assertEquals($uuid, $verdict->Guid);
    }

    public function testForUrlCleanUrl_GetsCleanResponse(): void
    {
        $uuid = $this->getUuid();

        $vaas = new Vaas($_ENV["VAAS_URL"], $this->_getDebugLogger());
        $vaas->Connect($this->getClientCredentialsGrantAuthenticator()->getToken());
        $verdict = $vaas->ForUrl("https://random-data-api.com/api/v2/beers", $uuid);

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
}
