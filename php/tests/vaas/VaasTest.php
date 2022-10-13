<?php

namespace VaasTesting;

require_once __DIR__ . "/vendor/autoload.php";

use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use VaasSdk\Vaas;
use Dotenv\Dotenv;
use Monolog\Formatter\JsonFormatter;
use Monolog\Handler\StreamHandler;
use Psr\Log\LoggerInterface;
use Monolog\Logger;
use Ramsey\Uuid\Rfc4122\UuidV4;

final class VaasTest extends TestCase
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

    public function testForSha256MaliciousSha256_GetsMaliciousResponse(): void
    {
        $uuid = $this->getUuid();
        $vaas = new Vaas($_ENV['CLIENT_ID'], $_ENV['CLIENT_SECRET'], $_ENV["TOKEN_URL"], $_ENV["VAAS_URL"], $this->_getDebugLogger());
        $this->assertEquals("Malicious", $vaas->ForSha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8", $uuid));
    }

    public function testVerdictResponseForSha256MaliciousSha256_GetsMaliciousResponse(): void
    {
        $uuid = $this->getUuid();
        $vaas = new Vaas($_ENV['CLIENT_ID'], $_ENV['CLIENT_SECRET'], $_ENV["TOKEN_URL"], $_ENV["VAAS_URL"], $this->_getDebugLogger());
        $verdictResponse = $vaas->VerdictResponseForSha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8", $uuid);
        $this->assertEquals("Malicious", $verdictResponse->verdict);
        $this->assertEquals($uuid, $verdictResponse->guid);
    }

    public function testForMultipleMaliciousSha256_GetsMaliciousResponses(): void
    {
        $uuid = $this->getUuid();
        $vaas = new Vaas($_ENV['CLIENT_ID'], $_ENV['CLIENT_SECRET'], $_ENV["TOKEN_URL"], $_ENV["VAAS_URL"], $this->_getDebugLogger());
        $this->assertEquals("Malicious", $vaas->ForSha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8", $uuid));
        $this->assertEquals("Malicious", $vaas->ForSha256("00000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c", $uuid));
        $this->assertEquals("Malicious", $vaas->ForSha256("00000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fd1a", $uuid));
    }

    public function testVerdictResponseForMultipleMaliciousSha256_GetsMaliciousResponses(): void
    {
        $uuid = $this->getUuid();
        $vaas = new Vaas($_ENV['CLIENT_ID'], $_ENV['CLIENT_SECRET'], $_ENV["TOKEN_URL"], $_ENV["VAAS_URL"], $this->_getDebugLogger());
        $verdictResponse1 = $vaas->VerdictResponseForSha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8", $uuid);
        $verdictResponse2 = $vaas->VerdictResponseForSha256("00000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c", $uuid);
        $verdictResponse3 = $vaas->VerdictResponseForSha256("00000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fd1a", $uuid);
        $this->assertEquals("Malicious", $verdictResponse1->verdict);
        $this->assertEquals($uuid, $verdictResponse1->guid);
        $this->assertEquals("Malicious", $verdictResponse2->verdict);
        $this->assertEquals($uuid, $verdictResponse1->guid);
        $this->assertEquals("Malicious", $verdictResponse1->verdict);
        $this->assertEquals($uuid, $verdictResponse3->guid);
    }

    public function testForSha256CleanSha256_GetsCleanResponse(): void
    {
        $uuid = $this->getUuid();
        $vaas = new Vaas($_ENV['CLIENT_ID'], $_ENV['CLIENT_SECRET'], $_ENV["TOKEN_URL"], $_ENV["VAAS_URL"], $this->_getDebugLogger());
        $this->assertEquals("Clean", $vaas->ForSha256("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23", $uuid));
    }

    public function testVerdictResponseForSha256CleanSha256_GetsCleanResponse(): void
    {
        $uuid = $this->getUuid();
        $vaas = new Vaas($_ENV['CLIENT_ID'], $_ENV['CLIENT_SECRET'], $_ENV["TOKEN_URL"], $_ENV["VAAS_URL"], $this->_getDebugLogger());
        $verdictResponse = $vaas->VerdictResponseForSha256("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23", $uuid);
        $this->assertEquals($uuid, $verdictResponse->guid);
        $this->assertEquals("Clean", $verdictResponse->verdict);
    }

    public function testForSha256AmtsoPupSample_GetsPupResponse(): void
    {
        $uuid = $this->getUuid();
        $vaas = new Vaas($_ENV['CLIENT_ID'], $_ENV['CLIENT_SECRET'], $_ENV["TOKEN_URL"], $_ENV["VAAS_URL"], $this->_getDebugLogger());
        $this->assertEquals("Pup", $vaas->ForSha256("d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad", $uuid));
    }
    public function testVerdictResponseForSha256AmtsoPupSample_GetsPupResponse(): void
    {
        $uuid = $this->getUuid();
        $vaas = new Vaas($_ENV['CLIENT_ID'], $_ENV['CLIENT_SECRET'], $_ENV["TOKEN_URL"], $_ENV["VAAS_URL"], $this->_getDebugLogger());
        $verdictResponse = $vaas->VerdictResponseForSha256("d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad", $uuid);
        $this->assertEquals("Pup", $verdictResponse->verdict);
        $this->assertEquals($uuid, $verdictResponse->guid);
    }

    public function testForMultipleCleanFiles_GetsCleanResponses(): void
    {
        $uuid = $this->getUuid();
        $vaas = new Vaas($_ENV['CLIENT_ID'], $_ENV['CLIENT_SECRET'], $_ENV["TOKEN_URL"], $_ENV["VAAS_URL"], $this->_getDebugLogger());
        $this->assertEquals("Clean", $vaas->ForSha256("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23", $uuid));
        $this->assertEquals("Clean", $vaas->ForSha256("1AFAFE9157FF5670BBEC8CE622F45D1CE51B3EE77B7348D3A237E232F06C5391", $uuid));
        $this->assertEquals("Clean", $vaas->ForSha256("4447FAACEFABA8F040822101E2A4103031660DE9139E70ECFF9AA3A89455A783", $uuid));
    }
    public function testVerdictResponseForSha256MultipleCleanFiles_GetsCleanResponses(): void
    {
        $uuid = $this->getUuid();
        $vaas = new Vaas($_ENV['CLIENT_ID'], $_ENV['CLIENT_SECRET'], $_ENV["TOKEN_URL"], $_ENV["VAAS_URL"], $this->_getDebugLogger());
        $verdictResponse1 = $vaas->VerdictResponseForSha256("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23", $uuid);
        $verdictResponse2 = $vaas->VerdictResponseForSha256("1AFAFE9157FF5670BBEC8CE622F45D1CE51B3EE77B7348D3A237E232F06C5391", $uuid);
        $verdictResponse3 = $vaas->VerdictResponseForSha256("4447FAACEFABA8F040822101E2A4103031660DE9139E70ECFF9AA3A89455A783", $uuid);
        $this->assertEquals("Clean", $verdictResponse1->verdict);
        $this->assertEquals($uuid, $verdictResponse1->guid);
        $this->assertEquals("Clean", $verdictResponse2->verdict);
        $this->assertEquals($uuid, $verdictResponse2->guid);
        $this->assertEquals("Clean", $verdictResponse3->verdict);
        $this->assertEquals($uuid, $verdictResponse3->guid);
   }

    public function testForSha256UnknownSha256_GetsUnknownResponse(): void
    {
        $uuid = $this->getUuid();
        $vaas = new Vaas($_ENV['CLIENT_ID'], $_ENV['CLIENT_SECRET'], $_ENV["TOKEN_URL"], $_ENV["VAAS_URL"], $this->_getDebugLogger());
        $this->assertEquals("Unknown", $vaas->ForSha256("00000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fbbb", $uuid));
    }

    public function testVerdictResponseForSha256UnknownSha256_GetsUnknownResponse(): void
    {
        $uuid = $this->getUuid();
        $vaas = new Vaas($_ENV['CLIENT_ID'], $_ENV['CLIENT_SECRET'], $_ENV["TOKEN_URL"], $_ENV["VAAS_URL"], $this->_getDebugLogger());
        $verdictResponse = $vaas->VerdictResponseForSha256("00000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fbbb", $uuid);
        $this->assertEquals("Unknown", $verdictResponse->verdict);
        $this->assertEquals($uuid, $verdictResponse->guid);
    }

    public function testForMultipleUnknownFiles_GetsUnknownResponses(): void
    {
        $uuid = $this->getUuid();
        $vaas = new Vaas($_ENV['CLIENT_ID'], $_ENV['CLIENT_SECRET'], $_ENV["TOKEN_URL"], $_ENV["VAAS_URL"], $this->_getDebugLogger());
        $this->assertEquals("Unknown", $vaas->ForSha256("110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8", $uuid));
        $this->assertEquals("Unknown", $vaas->ForSha256("11000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c", $uuid));
        $this->assertEquals("Unknown", $vaas->ForSha256("11000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fd1a", $uuid));
    }

    public function testVerdictResponseForMultipleUnknownFiles_GetsUnknownResponses(): void
    {
        $uuid = $this->getUuid();
        $vaas = new Vaas($_ENV['CLIENT_ID'], $_ENV['CLIENT_SECRET'], $_ENV["TOKEN_URL"], $_ENV["VAAS_URL"], $this->_getDebugLogger());
        $verdictResponse1 = $vaas->VerdictResponseForSha256("110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8", $uuid);
        $verdictResponse2 = $vaas->VerdictResponseForSha256("110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8", $uuid);
        $verdictResponse3 = $vaas->VerdictResponseForSha256("110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8", $uuid);
        $this->assertEquals("Unknown", $verdictResponse1->verdict);
        $this->assertEquals($uuid, $verdictResponse1->guid);
        $this->assertEquals("Unknown", $verdictResponse2->verdict);
        $this->assertEquals($uuid, $verdictResponse2->guid);
        $this->assertEquals("Unknown", $verdictResponse3->verdict);
        $this->assertEquals($uuid, $verdictResponse3->guid);
    }

    public function testForFileCleanFile_GetsCleanResponse(): void
    {
        $uuid = $this->getUuid();

        $cleanFile = pack("nvc*", 0x65, 0x0a, 0x67, 0x0a, 0x65, 0x0a, 0x62, 0x0a);
        $tmp = tmpfile();
        fwrite($tmp, $cleanFile);
        fseek($tmp, 0);

        $vaas = new Vaas($_ENV['CLIENT_ID'], $_ENV['CLIENT_SECRET'], $_ENV["TOKEN_URL"], $_ENV["VAAS_URL"], $this->_getDebugLogger());
        $this->assertEquals("Clean", $vaas->ForFile(stream_get_meta_data($tmp)['uri'], true, $uuid));
        fclose($tmp);
    }

    public function testVerdictResponseForFileCleanFile_GetsCleanResponse(): void
    {
        $uuid = $this->getUuid();

        $cleanFile = pack("nvc*", 0x65, 0x0a, 0x67, 0x0a, 0x65, 0x0a, 0x62, 0x0a);
        $tmp = tmpfile();
        fwrite($tmp, $cleanFile);
        fseek($tmp, 0);

        $vaas = new Vaas($_ENV['CLIENT_ID'], $_ENV['CLIENT_SECRET'], $_ENV["TOKEN_URL"], $_ENV["VAAS_URL"], $this->_getDebugLogger());
        $verdictResponse = $vaas->VerdictResponseForFile(stream_get_meta_data($tmp)['uri'], true, $uuid);
        $this->assertEquals("Clean", $verdictResponse->verdict);
        $this->assertEquals($uuid, $verdictResponse->guid);
        fclose($tmp);
    }

    public function testForFileMaliciousFile_GetsMaliciousResponse(): void
    {
        $uuid = $this->getUuid();

        $tmp = tmpfile();
        fwrite($tmp, "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*");
        fseek($tmp, 0);

        $vaas = new Vaas($_ENV['CLIENT_ID'], $_ENV['CLIENT_SECRET'], $_ENV["TOKEN_URL"], $_ENV["VAAS_URL"], $this->_getDebugLogger());
        $this->assertEquals("Malicious", $vaas->ForFile(stream_get_meta_data($tmp)['uri'], false, $uuid));
        fclose($tmp);
    }
    public function testVerdictResponseForFileMaliciousFile_GetsMaliciousResponse(): void
    {
        $uuid = $this->getUuid();

        $tmp = tmpfile();
        fwrite($tmp, "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*");
        fseek($tmp, 0);

        $vaas = new Vaas($_ENV['CLIENT_ID'], $_ENV['CLIENT_SECRET'], $_ENV["TOKEN_URL"], $_ENV["VAAS_URL"], $this->_getDebugLogger());
        $verdictResponse = $vaas->VerdictResponseForFile(stream_get_meta_data($tmp)['uri'], false, $uuid);
        $this->assertEquals("Malicious", $verdictResponse->verdict);
        $this->assertEquals($uuid, $verdictResponse->guid);
        fclose($tmp);
    }
    public function testForFileRandomFile_GetsCleanResponseAfterUpload(): void
    {
        $uuid = $this->getUuid();

        $tmp = tmpfile();
        fwrite($tmp, $uuid);
        fseek($tmp, 0);

        $vaas = new Vaas($_ENV['CLIENT_ID'], $_ENV['CLIENT_SECRET'], $_ENV["TOKEN_URL"], $_ENV["VAAS_URL"], $this->_getDebugLogger());
        $this->assertEquals("Clean", $vaas->ForFile(stream_get_meta_data($tmp)['uri'], true, $uuid));
        fclose($tmp);
    }

    public function testVerdictResponseForFileRandomFile_GetsCleanResponseAfterUpload(): void
    {
        $uuid = $this->getUuid();

        $tmp = tmpfile();
        fwrite($tmp, $uuid);
        fseek($tmp, 0);

        $vaas = new Vaas($_ENV['CLIENT_ID'], $_ENV['CLIENT_SECRET'], $_ENV["TOKEN_URL"], $_ENV["VAAS_URL"], $this->_getDebugLogger());
        $verdictResponse = $vaas->VerdictResponseForFile(stream_get_meta_data($tmp)['uri'], true, $uuid);
        $this->assertEquals("Clean", $verdictResponse->verdict);
        $this->assertEquals($uuid, $verdictResponse->guid);
        fclose($tmp);
    }

    public function testForMultipleMaliciousFilesWithCredentials_GetsMaliciousResponses(): void
    {

        $uuid = $this->getUuid();
        $vaas = new Vaas($_ENV['CLIENT_ID'], $_ENV['CLIENT_SECRET'], $_ENV["TOKEN_URL"], $_ENV["VAAS_URL"], $this->_getDebugLogger());
        $this->assertEquals("Malicious", $vaas->ForSha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8", $uuid));
        $this->assertEquals("Malicious", $vaas->ForSha256("00000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c", $uuid));
        $this->assertEquals("Malicious", $vaas->ForSha256("00000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fd1a", $uuid));
    }

    public function testForEmptyFile_GetsCleanResponse(): void
    {
        $uuid = $this->getUuid();

        $tmp = tmpfile();
        fwrite($tmp, "");
        fseek($tmp, 0);

        $vaas = new Vaas($_ENV['CLIENT_ID'], $_ENV['CLIENT_SECRET'], $_ENV["TOKEN_URL"], $_ENV["VAAS_URL"], $this->_getDebugLogger());
        $this->assertEquals("Clean", $vaas->ForFile(stream_get_meta_data($tmp)['uri'], true, $uuid));
        fclose($tmp);
    }

    /**
     * @outputBuffering disabled
     */
    private function getUuid(): string {
        $uuid = UuidV4::getFactory()->uuid4()->toString();
        echo "Generated UUID: $uuid \n";
        return $uuid;
    }
}
