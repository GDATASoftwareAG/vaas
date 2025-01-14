<?php

namespace VaasExamples;

use VaasSdk\Authentication\ClientCredentialsGrantAuthenticator;
use VaasSdk\Options\VaasOptions;
use VaasSdk\Vaas;

include_once("./vendor/autoload.php");


$authenticator = new ClientCredentialsGrantAuthenticator(
    clientId: getenv("CLIENT_ID"),
    clientSecret: getenv("CLIENT_SECRET"),
    tokenUrl: getenv("TOKEN_URL")
);

$options = new VaasOptions(
    useHashLookup: true,
    useCache: true,
    vaasUrl: getenv("VAAS_URL"),
    timeout: 300
);

$vaas = Vaas::builder()
    ->withAuthenticator($authenticator)
    ->withOptions($options)
    ->build();

// EICAR
$vaasVerdict = $vaas->forUrlAsync("https://secure.eicar.org/eicar.com")->await();
fwrite(STDOUT, "Verdict for $vaasVerdict->sha256 is " . $vaasVerdict->verdict->value . " \n");

// Some file
$vaasVerdict = $vaas->forUrlAsync("https://www.gdatasoftware.com/oem/verdict-as-a-service")->await();
fwrite(STDOUT, "Verdict for $vaasVerdict->sha256 is " . $vaasVerdict->verdict->value . " \n");
