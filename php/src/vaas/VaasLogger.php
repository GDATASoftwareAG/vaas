<?php

namespace VaasSdk;

use Psr\Log\LoggerInterface;
use Stringable;

class VaasLogger implements LoggerInterface
{

    public function emergency(string|Stringable $message, array $context = []): void
    {
        echo $message;
    }

    public function alert(string|Stringable $message, array $context = []): void
    {
        echo $message;
    }

    public function critical(string|Stringable $message, array $context = []): void
    {
        echo $message;
    }

    public function error(string|Stringable $message, array $context = []): void
    {
        echo $message;
    }

    public function warning(string|Stringable $message, array $context = []): void
    {
        echo $message;
    }

    public function notice(string|Stringable $message, array $context = []): void
    {
        echo $message;
    }

    public function info(string|Stringable $message, array $context = []): void
    {
        echo $message;
    }

    public function debug(string|Stringable $message, array $context = []): void
    {
        echo $message;
    }

    public function log($level, string|Stringable $message, array $context = []): void
    {
        echo $message;
    }
}
