<?php

namespace VaasSdk\Exceptions;

use Exception;

/**
 * The request is malformed or cannot be completed.
 * Recommended actions:
 * * Don't repeat the request.
 * * Log.
 * * Analyze the error.
 */
class VaasClientException extends Exception
{
    public function __construct(string $message = 'Client error', int $code = 0, Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}