<?php

namespace VaasSdk\Exceptions;

use Exception;

/**
 * The server encountered an internal error.
 * Recommended actions:
 * * You may retry the request after a certain delay.
 * * If the problem persists contact G DATA.
 */
class VaasServerException extends Exception
{
    public function __construct(?string $message)
    {
        if ($message == null) {
            parent::__construct("Server Error");
        } else {
            parent::__construct($message);
        }
    }
}