<?php

namespace VaasExamples;

use Dotenv\Dotenv;
use VaasSdk\ClientCredentialsGrantAuthenticator;
use VaasSdk\Vaas;

include_once("./vendor/autoload.php");

$dotenv = Dotenv::createUnsafeImmutable(__DIR__);
$dotenv->safeLoad();

$authenticator = new ClientCredentialsGrantAuthenticator(
    getenv("CLIENT_ID"),
    getenv("CLIENT_SECRET"),
    getenv("TOKEN_URL") ?? "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"
);
$vaas = new Vaas(
    getenv("VAAS_URL") ?? "wss://gateway.production.vaas.gdatasecurity.de", null, $authenticator
);

use Amp\Pipeline\Pipeline;

Pipeline::generate(function (): int { return 0; })
    ->take(100) // Take only 10 values from the generation function.
    ->concurrent(8)
    ->forEach(function (int $value) use ($vaas): void {
        $vaasVerdict = $vaas->ForSha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
        fwrite(STDOUT, "Verdict for $vaasVerdict->Sha256 is " . $vaasVerdict->Verdict->value . " \n");;
    });
