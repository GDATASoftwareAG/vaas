<?php

namespace VaasSdk\Exceptions;

use Exception;

class UploadFailedException extends Exception
{
    function __construct(string $message, int $code) {
        parent::__construct($message, $code);
    }
}
