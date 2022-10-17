<?php

namespace VaasExamples;

use VaasSdk\ClientCredentialsGrantAuthenticator;
use VaasSdk\Vaas;

include_once("./vendor/autoload.php");

$authenticator = new ClientCredentialsGrantAuthenticator(
    getenv("CLIENT_ID"),
    getenv("CLIENT_SECRET"),
    "https://keycloak-vaas.gdatasecurity.de/realms/vaas/protocol/openid-connect/token"
);
$vaas = new Vaas(
    "wss://gateway-vaas.gdatasecurity.de"
);
$vaas->Connect($authenticator->getToken());
$scanPath = getenv("SCAN_PATH");
fwrite(STDOUT, $vaas->ForFile("./$scanPath") . "\n");
