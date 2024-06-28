<?php

namespace VaasTesting;

use Dotenv\Dotenv;
use Monolog\Formatter\LineFormatter;
use Monolog\Handler\StreamHandler;
use Monolog\Level;
use Monolog\Logger;
use Psr\Log\LoggerInterface;
use VaasSdk\ClientCredentialsGrantAuthenticator;
use VaasSdk\Vaas;
use VaasSdk\VaasOptions;

function setUpDotEnv(): void
{
    // TODO: Test if this respects environment variables or only .env
    $dotenv = Dotenv::createImmutable(__DIR__);
    $dotenv->safeLoad();
}

function getVaas(bool $useCache = false, bool $useHashLookup = true): Vaas
{
    return new Vaas($_ENV["VAAS_URL"], getDebugLogger(), getClientCredentialsGrantAuthenticator(), new VaasOptions($useCache, $useHashLookup));
}

function getClientCredentialsGrantAuthenticator(): ClientCredentialsGrantAuthenticator
{
    return new ClientCredentialsGrantAuthenticator(
        $_ENV['CLIENT_ID'],
        $_ENV['CLIENT_SECRET'],
        $_ENV["TOKEN_URL"]
    );
}

function getDebugLogger(): LoggerInterface
{
    global $argv;
    $monoLogger = new Logger("VaaS");

    // --debug causes issues in PhpStorm
    //$isDebug = in_array("--debug", $argv);
    $isDebug = true;
    $streamHandler = new StreamHandler(
        STDOUT,
        $isDebug ? Level::Debug : Level::Info
    );

    $formatter = new LineFormatter(null, null, true, true);

    //$streamHandler->setFormatter(new JsonFormatter());
    $streamHandler->setFormatter($formatter);
    $monoLogger->pushHandler($streamHandler);
    return $monoLogger;
}
