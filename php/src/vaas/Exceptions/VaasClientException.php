<?php

namespace VaasSdk\Exceptions;

use Exception;

/**
 * The server encountered an internal error.
 * Recommended actions:
 * * You may retry the request after a certain delay.
 * * If the problem persists contact G DATA.
 */
class VaasClientException extends Exception
{
    public function __construct(?string $message)
    {
        if ($message == null) {
            parent::__construct("Client Error");
        } else {
            parent::__construct($message);
        }
    }
}