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
$vaasVerdict = $vaas->forUrlAsync("https://secure.eicar.org/eicar.com")->await();
fwrite(STDOUT, "Verdict for $vaasVerdict->sha256 is " . $vaasVerdict->verdict->value . " \n");
// SOMEFILE
$vaasVerdict = $vaas->forUrlAsync("https://www.gdatasoftware.com/oem/verdict-as-a-service")->await();
fwrite(STDOUT, "Verdict for $vaasVerdict->sha256 is " . $vaasVerdict->verdict->value . " \n");
