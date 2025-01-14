<?php

namespace VaasTesting;

use PHPUnit\Framework\TestCase;
use VaasSdk\Exceptions\FileDoesNotExistException;
use VaasSdk\Exceptions\InvalidSha256Exception;
use VaasSdk\Sha256;

final class Sha256Test extends TestCase
{
    const VALID_SHA256 = "df6f184e0235c88868668c3f9434528a59377cedb18e305abdb1adea19e93be1";
    const VALID_FILE   = __DIR__ . "/testfile";

    public function testIsValidGetsValidSha256ReturnsTrue(): void
    {
        $this->assertTrue(Sha256::IsValid(Sha256Test::VALID_SHA256)->await());
    }

    public function testIsValidGetsInvalidSha256ReturnsFalse(): void
    {
        $this->assertFalse(Sha256::IsValid("00005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8")->await());
    }

    /**
     * @throws InvalidSha256Exception
     */
    public function testTryFromStringGetsValidSha256ReturnsCorrectSha256(): void
    {
        $calculatedSha256 = Sha256::TryFromString(Sha256Test::VALID_SHA256)->await();
        $this->assertEquals(Sha256Test::VALID_SHA256, $calculatedSha256);
    }

    public function testTryFromStringGetsInvalidSha256ThrowsInvalidSha256Exception(): void
    {
        $this->expectException(InvalidSha256Exception::class);
        Sha256::TryFromString("00005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8")->await();
    }

    /**
     * @throws InvalidSha256Exception
     * @throws FileDoesNotExistException
     */
    public function testTryFromFileGetsValidSha256ReturnsTrue(): void
    {
        $calculatedSha256 = Sha256::TryFromFile(Sha256Test::VALID_FILE)->await();
        $this->assertEquals(Sha256Test::VALID_SHA256, $calculatedSha256);
    }

    /**
     * @throws InvalidSha256Exception
     */
    public function testTryFromFileGetsInvalidPathThrowsFileDoesNotExistException(): void
    {
        $this->expectException(FileDoesNotExistException::class);
        Sha256::TryFromFile("./filedoesnotexist")->await();
    }
}