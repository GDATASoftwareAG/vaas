<?php

namespace VaasExamples;

use VaasSdk\Authentication\Authenticator;
use VaasSdk\Authentication\GrantType;
use VaasSdk\Options\AuthenticationOptions;
use VaasSdk\Vaas;

include_once("./vendor/autoload.php");

$credentials = new AuthenticationOptions(
    grantType: GrantType::CLIENT_CREDENTIALS,
    clientId: getenv("CLIENT_ID"),
    clientSecret: getenv("CLIENT_SECRET")
);

$authenticator = new Authenticator($credentials);

$vaas = new Vaas($authenticator);

// EICAR
$vaasVerdict = $vaas->forSha256Async("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8")->await();
fwrite(STDOUT, "Verdict for $vaasVerdict->Sha256 is " . $vaasVerdict->Verdict->value . " \n");
// SOMEFILE
$vaasVerdict = $vaas->forSha256Async("70caea443deb0d0a890468f9ac0a9b1187676ba3e66eb60a722b187107eb1ea8")->await();
fwrite(STDOUT, "Verdict for $vaasVerdict->Sha256 is " . $vaasVerdict->Verdict->value . " \n");
