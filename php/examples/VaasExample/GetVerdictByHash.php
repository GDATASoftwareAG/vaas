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

// EICAR
$vaasVerdict = $vaas->ForSha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
fwrite(STDOUT, "Verdict for $vaasVerdict->Sha256 is " . $vaasVerdict->Verdict->value . " \n");
// SOMEFILE
$vaasVerdict = $vaas->ForSha256("70caea443deb0d0a890468f9ac0a9b1187676ba3e66eb60a722b187107eb1ea8");
fwrite(STDOUT, "Verdict for $vaasVerdict->Sha256 is " . $vaasVerdict->Verdict->value . " \n");
