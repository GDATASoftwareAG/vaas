<?php

namespace VaasExamples;

use VaasSdk\ClientCredentialsGrantAuthenticator;
use VaasSdk\Exceptions\InvalidSha256Exception;
use VaasSdk\Exceptions\TimeoutException;
use VaasSdk\Exceptions\VaasAuthenticationException;
use VaasSdk\ResourceOwnerPasswordGrantAuthenticator;
use VaasSdk\Vaas;

$USE_RESOURCE_OWNER_PASSWORD_GRANT_AUTHENTICATOR = false;

// If you got a username and password from us, you can use the ResourceOwnerPasswordAuthenticator like this
if ($USE_RESOURCE_OWNER_PASSWORD_GRANT_AUTHENTICATOR){
    $authenticator = new ResourceOwnerPasswordGrantAuthenticator(
        "vaas-customer",
        getenv("VAAS_USER_NAME"),
        getenv("VAAS_PASSWORD"),
        getenv("TOKEN_URL")
    );
}
// You may use self registration and create a new username and password for the
// ResourceOwnerPasswordAuthenticator by yourself like the example above on https://vaas.gdata.de/login

// If you got a client id and client secret from us, you can use the ClientCredentialsGrantAuthenticator like this
else{
    $authenticator = new ClientCredentialsGrantAuthenticator(
        getenv("CLIENT_ID"),
        getenv("CLIENT_SECRET"),
        getenv("TOKEN_URL")
    );
}

$vaas = new Vaas(
    getenv("VAAS_URL"), null, $authenticator
);

// Get verdict for an eicar hash
try {
    $vaasVerdict = $vaas->ForSha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
} catch (InvalidSha256Exception $e) {
    fwrite(STDERR, "Invalid sha256: " . $e->getMessage() . "\n");
    exit(1);
} catch (TimeoutException $e) {
    fwrite(STDERR, "Timeout: " . $e->getMessage() . "\n");
    exit(1);
} catch (VaasAuthenticationException $e) {
    fwrite(STDERR, "Authentication failed: " . $e->getMessage() . "\n");
    exit(1);
}
fwrite(STDOUT, "Verdict for $vaasVerdict->Sha256 is $vaasVerdict->Verdict \n");
