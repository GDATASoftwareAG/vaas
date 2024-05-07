<?php

require 'vendor/autoload.php';

use VaasSdk\ClientCredentialsGrantAuthenticator;
use VaasSdk\Message\VerdictRequest;
use VaasSdk\VaasWebSocket;
use function Amp\async;

// $url = "wss://gateway.develop.vaas.gdatasecurity.de";
$url = "wss://gateway.production.vaas.gdatasecurity.de";

$authenticator = new ClientCredentialsGrantAuthenticator(
    "vaas-integration-test",
    "",
    "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"
);

$webSocket = new VaasWebSocket($url, $authenticator);

$verdictResponse = $webSocket->sendRequest(new VerdictRequest("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2", null, ""));
print_r($verdictResponse->await());

//while (true){
//    Amp\delay(0.01);
//    print ".";
//}
//$cancellation = new Amp\TimeoutCancellation(10);
//
//$future->await($cancellation);
