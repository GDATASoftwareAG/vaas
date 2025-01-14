<?php

namespace VaasSdk\Authentication;

use Amp\Cancellation;

interface AuthenticatorInterface
{
    public function getTokenAsync(?Cancellation $cancellation = null): string;
}