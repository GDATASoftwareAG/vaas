<?php

namespace VaasExamples;

use VaasSdk\Authentication\ClientCredentialsGrantAuthenticator;
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


$scanPath = getenv("SCAN_PATH");
$vaasVerdict = $vaas->forFileAsync($scanPath)->await();

fwrite(STDOUT, "Verdict for $vaasVerdict->sha256 is " . $vaasVerdict->verdict->value . " \n");
