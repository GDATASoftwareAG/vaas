<?php

namespace VaasSdk\Authentication;

interface AuthenticatorInterface {
    public function getToken(): string;
}
