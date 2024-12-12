<?php

namespace VaasExamples;

use VaasSdk\Authentication\Authenticator;
use VaasSdk\Authentication\GrantType;
use VaasSdk\Options\AuthenticationOptions;
use VaasSdk\Vaas;

// If you got a username and password from us, you can use the ResourceOwnerPasswordAuthenticator like this

// $credentials = new AuthenticationOptions(
//     grantType: GrantType::PASSWORD,
//     clientId: getenv("VAAS_CLIENT_ID"),
//     username: getenv("VAAS_USER_NAME"),
//     password: getenv("VAAS_PASSWORD")
// );
    
// You may use self registration and create a new username and password for the
// `Password` authentication method by yourself like the example above on https://vaas.gdata.de/login

// If you got a client id and client secret from us, you can use the `Client Credentials` authentication method like this

$credentials = new AuthenticationOptions(
    grantType: GrantType::CLIENT_CREDENTIALS,
    clientId: getenv("CLIENT_ID"),
    clientSecret: getenv("CLIENT_SECRET")
);

$authenticator = new Authenticator($credentials);
$vaas = new Vaas($authenticator);

// Get verdict for an eicar hash
$vaasVerdict = $vaas->forSha256Async("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8")->await();
fwrite(STDOUT, "Verdict for $vaasVerdict->sha256 is $vaasVerdict->verdict->value \n");
