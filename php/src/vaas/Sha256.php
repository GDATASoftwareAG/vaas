<?php

namespace VaasSdk;

use Amp\Future;
use VaasSdk\Exceptions\FileDoesNotExistException;
use VaasSdk\Exceptions\InvalidSha256Exception;
use function Amp\async;

class Sha256
{
    private string $_hash;

    /**
     * Gets Sha256 from file
     * @param string $path the path of the file to hash
     * @return Future that resolves as the sha256 object
     * @throws FileDoesNotExistException if the file does not exist
     * @throws InvalidSha256Exception if the hash is invalid
     */
    public static function TryFromFile(string $path): Future
    {
        return async(function () use ($path) {
            if (!file_exists($path)) {
                throw new FileDoesNotExistException();
            }

            $hashString = hash_file("sha256", $path);

            if (Sha256::IsValid($hashString)->await()) {
                $sha256 = new Sha256();
                $sha256->_hash = $hashString;
                return $sha256;
            }

            throw new InvalidSha256Exception();
        });
    }

    /**
     * Gets Sha256 from string
     * @param string $hashString the string to create the hash from
     * @return Future that resolves to the sha256 object
     * @throws InvalidSha256Exception if the hash is invalid
     */
    public static function TryFromString(string $hashString): Future
    {
        return async(function () use($hashString) {
            if (Sha256::IsValid($hashString)->await()) {
                $sha256 = new Sha256();
                $sha256->_hash = $hashString;
                return $sha256;
            }
            throw new InvalidSha256Exception();
        });
    }

    /**
     * Validates a hash to be a valid sha256
     * @param string $hash the string to validate
     * @return Future that resolves as true if sha256 is valid
     */
    public static function IsValid(string $hash): Future
    {
        return async(function () use ($hash) {
            if (preg_match("/^([a-f0-9]{64})$/", strtolower($hash)) == 1) {
                return true;
            } else {
                return false;
            }
        });
    }
            

    public function __toString(): string
    {
        return $this->_hash;
    }
}