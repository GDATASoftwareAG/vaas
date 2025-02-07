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

$vaas = Vaas::builder()
    ->withAuthenticator($authenticator)
    ->build();


// EICAR
$vaasVerdict = $vaas->forUrlAsync("https://secure.eicar.org/eicar.com")->await();
fwrite(STDOUT, "Verdict for $vaasVerdict->sha256 is " . $vaasVerdict->verdict->value . " \n");

// Some file
$vaasVerdict = $vaas->forUrlAsync("https://www.gdatasoftware.com/oem/verdict-as-a-service")->await();
fwrite(STDOUT, "Verdict for $vaasVerdict->sha256 is " . $vaasVerdict->verdict->value . " \n");
