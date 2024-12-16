<?php

namespace VaasSdk\Exceptions;

use Exception;

class FileDoesNotExistException extends Exception
{
    public function __construct(string $message = 'File does not exist', int $code = 0, Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}