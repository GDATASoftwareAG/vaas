<?php

namespace VaasSdk\Authentication;

use Amp\Cancellation;

interface AuthenticatorInterface
{
    public function getToken(?Cancellation $cancellation = null): string;
}