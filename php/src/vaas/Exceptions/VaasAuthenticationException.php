<?php

namespace VaasSdk\Exceptions;

use Exception;

class VaasAuthenticationException extends Exception
{
    public function __construct(string $message = 'Authentication failed', int $code = 0, Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}