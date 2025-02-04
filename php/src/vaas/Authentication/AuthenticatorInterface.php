<?php

namespace VaasSdk\Authentication;

use Amp\Cancellation;
use Amp\Future;

interface AuthenticatorInterface
{
    public function getTokenAsync(?Cancellation $cancellation = null): Future;
}