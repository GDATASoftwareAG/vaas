<?php

namespace VaasSdk;

use VaasSdk\Exceptions\FileDoesNotExistException;
use VaasSdk\Exceptions\InvalidSha256Exception;

class Sha256
{
    private string $hash;

    /**
     * Gets Sha256 from file
     *
     * @param string $path the path of the file to hash
     */
    public static function TryFromFile(string $path): Sha256
    {
        if (!file_exists($path)) {
            throw new FileDoesNotExistException();
        }

        $hashString = hash_file("sha256", $path);

        if (Sha256::IsValid($hashString)) {
            $sha256 = new Sha256();
            $sha256->hash = $hashString;
            return $sha256;
        }
        throw new InvalidSha256Exception();
    }

    /**
     * Gets Sha256 from string
     *
     * @param string $hashString the string to create the hash from
     */
    public static function TryFromString(string $hashString): Sha256
    {
        if (Sha256::IsValid($hashString)) {
            $sha256 = new Sha256();
            $sha256->hash = $hashString;
            return $sha256;
        }
        throw new InvalidSha256Exception();
    }
    
    /**
     * Validates a hash to be a valid sha256
     *
     * @param string $hash the string to validate
     */
    public static function IsValid(string $hash): bool
    {
        if (preg_match("/^([a-f0-9]{64})$/", strtolower($hash)) == 1) {
            return true;
        } else {
            return false;
        }
    }

    public function __toString(): string
    {
        return $this->hash;
    }
}
