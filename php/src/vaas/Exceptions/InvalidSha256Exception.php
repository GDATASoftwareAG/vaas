<?php

namespace VaasSdk\Exceptions;

use Exception;

class InvalidSha256Exception extends Exception
{
    public function __construct(string $message = 'Invalid SHA256 hash', int $code = 0, Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}