<?php

namespace VaasExamples;

use VaasSdk\Authentication\ClientCredentialsGrantAuthenticator;
use VaasSdk\Vaas;

include_once("./vendor/autoload.php");

$authenticator = new ClientCredentialsGrantAuthenticator(
    getenv("CLIENT_ID"),
    getenv("CLIENT_SECRET"),
    getenv("TOKEN_URL") ?: "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"
);

$vaas = (new Vaas())
    ->WithUrl(getenv("VAAS_URL") ?? "wss://gateway.production.vaas.gdatasecurity.de")
    ->build();

$vaas->Connect($authenticator->getToken());
$scanPath = getenv("SCAN_PATH");
$vaasVerdict = $vaas->ForFile($scanPath);

fwrite(STDOUT, "Verdict for $vaasVerdict->Sha256 is " . $vaasVerdict->Verdict->value . " \n");
