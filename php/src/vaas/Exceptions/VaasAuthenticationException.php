<?php

namespace VaasSdk\Exceptions;

use Exception;

/**
 * The Vaas authentication failed.
 * Recommended actions:
 * * Double-check your credentials in the authenticator object.
 * * Check if your authenticator connects to the correct token endpoint.
 * * Check if the token endpoint is reachable.
 * * If your problem persists contact G DATA.
 */
class VaasAuthenticationException extends Exception
{
    public function __construct(string $message = 'Authentication failed', int $code = 0, Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}