<?php

namespace VaasExamples;

use VaasSdk\ClientCredentialsGrantAuthenticator;
use VaasSdk\Vaas;

include_once("./vendor/autoload.php");

$authenticator = new ClientCredentialsGrantAuthenticator(
    getenv("CLIENT_ID"),
    getenv("CLIENT_SECRET"),
    getenv("TOKEN_URL") ?? "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token");
$vaas = new Vaas(
    getenv("VAAS_URL") ?? "wss://gateway.production.vaas.gdatasecurity.de"
);
$vaas->Connect($authenticator->getToken());

// EICAR
$vaasVerdict = $vaas->ForUrl("https://secure.eicar.org/eicar.com");
fwrite(STDOUT, "Verdict for $vaasVerdict->Sha256 is $vaasVerdict->Verdict \n");
// SOMEFILE
$vaasVerdict = $vaas->ForUrl("https://www.gdatasoftware.com/oem/verdict-as-a-service");
fwrite(STDOUT, "Verdict for $vaasVerdict->Sha256 is $vaasVerdict->Verdict \n");
