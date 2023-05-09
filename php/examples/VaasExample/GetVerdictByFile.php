<?php

namespace VaasExamples;

use Monolog\Logger;
use VaasSdk\ClientCredentialsGrantAuthenticator;
use VaasSdk\Vaas;

include_once("./vendor/autoload.php");

$authenticator = new ClientCredentialsGrantAuthenticator(
    getenv("CLIENT_ID"),
    getenv("CLIENT_SECRET"),
    "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"
);

$vaas = new Vaas(
    "wss://gateway.production.vaas.gdatasecurity.de"
);

$vaas->Connect($authenticator->getToken());
$scanPath = getenv("SCAN_PATH");
$vaasVerdict = $vaas->ForFile($scanPath);

fwrite(STDOUT, "Verdict for $vaasVerdict->Sha256 is $vaasVerdict->Verdict \n");
