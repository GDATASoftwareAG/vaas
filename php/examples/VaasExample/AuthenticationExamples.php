<?php

namespace VaasExamples;

use VaasSdk\ClientCredentialsGrantAuthenticator;
use VaasSdk\Exceptions\InvalidSha256Exception;
use VaasSdk\Exceptions\TimeoutException;
use VaasSdk\Exceptions\VaasAuthenticationException;
use VaasSdk\ResourceOwnerPasswordAuthenticator;
use VaasSdk\Vaas;

// If you got a username and password from us, you can use the ResourceOwnerPasswordAuthenticator like this
$authenticator = new ResourceOwnerPasswordAuthenticator(
    getenv("CLIENT_ID"),
    getenv("USER_NAME"),
    getenv("PASSWORD"),
    getenv("TOKEN_URL")
);
// If you got a client id with a link you may use self registration and create a new username and password for the
// ResourceOwnerPasswordAuthenticator by yourself like the example above.

// If you got a client id and client secret from us, you can use the ClientCredentialsGrantAuthenticator like this
$authenticator = new ClientCredentialsGrantAuthenticator(
    getenv("CLIENT_ID"),
    getenv("CLIENT_SECRET"),
    getenv("TOKEN_URL")
);

$vaas = new Vaas(
    getenv("VAAS_URL")
);

try {
    $vaas->Connect($authenticator->getToken());
} catch (VaasAuthenticationException $e) {
    fwrite(STDERR, "Authentication failed: " . $e->getMessage() . "\n");
    exit(1);
}

// Get verdict for an eicar hash
try {
    $vaasVerdict = $vaas->ForSha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
} catch (InvalidSha256Exception $e) {
    fwrite(STDERR, "Invalid sha256: " . $e->getMessage() . "\n");
    exit(1);
} catch (TimeoutException $e) {
    fwrite(STDERR, "Timeout: " . $e->getMessage() . "\n");
    exit(1);
}
fwrite(STDOUT, "Verdict for $vaasVerdict->Sha256 is $vaasVerdict->Verdict \n");
