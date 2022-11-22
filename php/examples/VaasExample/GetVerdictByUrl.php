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

// EICAR
$vaasVerdict = $vaas->ForUrl("https://secure.eicar.org/eicar.com");
fwrite(STDOUT, "Verdict for $vaasVerdict->Sha256 is $vaasVerdict->Verdict \n");
// SOMEFILE
$vaasVerdict = $vaas->ForUrl("https://www.gdatasoftware.com/oem/verdict-as-a-service");
fwrite(STDOUT, "Verdict for $vaasVerdict->Sha256 is $vaasVerdict->Verdict \n");
