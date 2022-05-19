<?php

namespace VaasTesting;

require_once "./vendor/autoload.php";

use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use VaasSdk\Vaas;
use VaasSdk\Exceptions\InvalidSha256Exception;
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
        if (getenv("VAAS_TOKEN") !== false) {
            $_ENV["VAAS_TOKEN"] = getenv("VAAS_TOKEN");
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
        $uuid = UuidV4::getFactory()->uuid4()->toString();
        $vaas = new Vaas($_ENV['VAAS_TOKEN'], $this->_getDebugLogger());
        $this->assertEquals("Malicious", $vaas->ForSha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8", $uuid));
    }

    public function testForMultipleMaliciousFiles_GetsMaliciousResponses(): void
    {
        $uuid = UuidV4::getFactory()->uuid4()->toString();
        $vaas = new Vaas($_ENV['VAAS_TOKEN'], $this->_getDebugLogger());
        $this->assertEquals("Malicious", $vaas->ForSha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8", $uuid));
        $this->assertEquals("Malicious", $vaas->ForSha256("00000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c", $uuid));
        $this->assertEquals("Malicious", $vaas->ForSha256("00000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fd1a", $uuid));
    }

    public function testForSha256CleanSha256_GetsCleanResponse(): void
    {
        $uuid = UuidV4::getFactory()->uuid4()->toString();
        $vaas = new Vaas($_ENV['VAAS_TOKEN'], $this->_getDebugLogger());
        $this->assertEquals("Clean", $vaas->ForSha256("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23", $uuid));
    }

    public function testForMultipleCleanFiles_GetsCleanResponses(): void
    {
        $uuid = UuidV4::getFactory()->uuid4()->toString();
        $vaas = new Vaas($_ENV['VAAS_TOKEN'], $this->_getDebugLogger());
        $this->assertEquals("Clean", $vaas->ForSha256("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23", $uuid));
        $this->assertEquals("Clean", $vaas->ForSha256("1AFAFE9157FF5670BBEC8CE622F45D1CE51B3EE77B7348D3A237E232F06C5391", $uuid));
        $this->assertEquals("Clean", $vaas->ForSha256("4447FAACEFABA8F040822101E2A4103031660DE9139E70ECFF9AA3A89455A783", $uuid));
    }

    public function testForSha256UnknownSha256_GetsUnknownResponse(): void
    {
        $uuid = UuidV4::getFactory()->uuid4()->toString();
        $vaas = new Vaas($_ENV['VAAS_TOKEN'], $this->_getDebugLogger());
        $this->assertEquals("Unknown", $vaas->ForSha256("00000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fbbb", $uuid));
    }

    public function testForMultipleUnknownFiles_GetsUnknownResponses(): void
    {
        $uuid = UuidV4::getFactory()->uuid4()->toString();
        $vaas = new Vaas($_ENV['VAAS_TOKEN'], $this->_getDebugLogger());
        $this->assertEquals("Unknown", $vaas->ForSha256("110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8", $uuid));
        $this->assertEquals("Unknown", $vaas->ForSha256("11000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c", $uuid));
        $this->assertEquals("Unknown", $vaas->ForSha256("11000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fd1a", $uuid));
    }

    public function testForFileCleanFile_GetsCleanResponse(): void
    {
        $uuid = UuidV4::getFactory()->uuid4()->toString();

        $cleanFile = pack("nvc*", 0x65, 0x0a, 0x67, 0x0a, 0x65, 0x0a, 0x62, 0x0a);
        $tmp = tmpfile();
        fwrite($tmp, $cleanFile);
        fseek($tmp, 0);

        $vaas = new Vaas($_ENV['VAAS_TOKEN'], $this->_getDebugLogger());
        $this->assertEquals("Clean", $vaas->ForFile(stream_get_meta_data($tmp)['uri'], true, $uuid));
        fclose($tmp);
    }

    public function testForFileMaliciousFile_GetsMaliciousResponse(): void
    {
        $uuid = UuidV4::getFactory()->uuid4()->toString();

        $tmp = tmpfile();
        fwrite($tmp, "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*");
        fseek($tmp, 0);

        $vaas = new Vaas($_ENV['VAAS_TOKEN'], $this->_getDebugLogger());
        $this->assertEquals("Malicious", $vaas->ForFile(stream_get_meta_data($tmp)['uri'], false, $uuid));
        fclose($tmp);
    }

    public function testForFileRandomFile_GetsCleanResponseAfterUpload(): void
    {
        $uuid = UuidV4::getFactory()->uuid4()->toString();

        $tmp = tmpfile();
        fwrite($tmp, $uuid);
        fseek($tmp, 0);

        $vaas = new Vaas($_ENV['VAAS_TOKEN'], $this->_getDebugLogger());
        $this->assertEquals("Clean", $vaas->ForFile(stream_get_meta_data($tmp)['uri'], true, $uuid));
        fclose($tmp);
    }
}
