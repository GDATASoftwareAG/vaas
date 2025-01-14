<?php

namespace VaasSdk\Exceptions;

use Exception;

class VaasClientException extends Exception
{
    public function __construct(string $message = 'Client error', int $code = 0, Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}