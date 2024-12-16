<?php

namespace VaasExamples;

use VaasSdk\Authentication\ClientCredentialsGrantAuthenticator;
use VaasSdk\Sha256;
use VaasSdk\Vaas;

// If you got a username and password from us, you can use the ResourceOwnerPasswordAuthenticator like this

// $authenticator = new ResourceOwnerPasswordGrantAuthenticator(
//     clientId: getenv("CLIENT_ID"),
//     username: getenv("USERNAME"),
//     password: getenv("PASSWORD"),
//     tokenUrl: getenv("TOKEN_URL")
// );
    
// You may use self registration and create a new username and password for the
// `Password` authentication method by yourself like the example above on https://vaas.gdata.de/login

// If you got a client id and client secret from us, you can use the `Client Credentials` authentication method like this

$authenticator = new ClientCredentialsGrantAuthenticator(
    clientId: getenv("CLIENT_ID"),
    clientSecret: getenv("CLIENT_SECRET"),
    tokenUrl: getenv("TOKEN_URL")
);

$vaas = (new Vaas())
    ->withAuthenticator($authenticator)
    ->build();

// Get verdict for an eicar hash
$vaasVerdict = $vaas->forSha256Async(Sha256::TryFromString("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8"))->await();
fwrite(STDOUT, "Verdict for $vaasVerdict->sha256 is $vaasVerdict->verdict->value \n");
