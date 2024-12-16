<?php

namespace VaasExamples;

use VaasSdk\Authentication\ClientCredentialsGrantAuthenticator;
use VaasSdk\Sha256;
use VaasSdk\Vaas;

include_once("./vendor/autoload.php");


$authenticator = new ClientCredentialsGrantAuthenticator(
    clientId: getenv("CLIENT_ID"),
    clientSecret: getenv("CLIENT_SECRET"),
    tokenUrl: getenv("TOKEN_URL")
);

$vaas = (new Vaas())
    ->withAuthenticator($authenticator)
    ->build();


// EICAR
$vaasVerdict = $vaas->forSha256Async(Sha256::TryFromString("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8"))->await();
fwrite(STDOUT, "Verdict for $vaasVerdict->sha256 is " . $vaasVerdict->verdict->value . " \n");


// Some file
$vaasVerdict = $vaas->forSha256Async(Sha256::TryFromString("70caea443deb0d0a890468f9ac0a9b1187676ba3e66eb60a722b187107eb1ea8"))->await();
fwrite(STDOUT, "Verdict for $vaasVerdict->sha256 is " . $vaasVerdict->verdict->value . " \n");
