<?php

namespace VaasSdk\Authentication;

use Amp\Cancellation;
use Amp\Future;

interface AuthenticatorInterface
{
    /**
     * Gets the access token asynchronously.
     * If the token is still valid, it will be returned immediately.
     * If the token is expired, a new token will be requested.
     * @param Cancellation|null $cancellation Cancellation token
     * @return Future Future that resolves to the access token as string
     * @throws VaasAuthenticationException The Vaas authentication failed. Recommended actions: Double-check your credentials in the authenticator object. Check if your authenticator connects to the correct token endpoint. Check if the token endpoint is reachable. If your problem persists contact G DATA.
     */
    public function getTokenAsync(?Cancellation $cancellation = null): Future;
}