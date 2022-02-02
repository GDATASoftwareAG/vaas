<?php
namespace VaasTesting;

require_once "./vendor/autoload.php";

use PHPUnit\Framework\TestCase;
use VaasSdk\Sha256;
use VaasSdk\Exceptions\InvalidSha256Exception;
use VaasSdk\Exceptions\FileDoesNotExistException;

final class Sha256Test extends TestCase
{
    const VALIDSHA256 = "df6f184e0235c88868668c3f9434528a59377cedb18e305abdb1adea19e93be1";
    const VALIDFILE   = "./testfile";

    public function testIsValidGetsValidSha256ReturnsTrue(): void
    {
        $this->assertTrue(Sha256::IsValid(Sha256Test::VALIDSHA256));
    }

    public function testIsValidGetsInvalidSha256ReturnsFalse(): void
    {
        $this->assertFalse(Sha256::IsValid("00005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8"));
    }

    public function testTryFromStringGetsValidSha256ReturnsCorrectSha256(): void
    {
        $calculatedSha256 = Sha256::TryFromString(Sha256Test::VALIDSHA256);
        $this->assertEquals(Sha256Test::VALIDSHA256, $calculatedSha256); 
    }

    public function testTryFromStringGetsInvalidSha256ThrowsInvalidSha256Exception(): void
    {
        $this->expectException(InvalidSha256Exception::class);
        Sha256::TryFromString("00005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
    }

    public function testTryFromFileGetsValidSha256ReturnsTrue(): void
    {
        $calculatedSha256 = Sha256::TryFromFile(Sha256Test::VALIDFILE);
        $this->assertEquals(Sha256Test::VALIDSHA256, $calculatedSha256); 
    }

    public function testTryFromFileGetsInvalidPathThrowsFileDoesNotExistException(): void
    {
        $this->expectException(FileDoesNotExistException::class);
        Sha256::TryFromFile("./filedoesnotexist");
    }
}
