<?php

namespace VaasSdk;

interface AuthenticatorInterface
{
    public function getToken(): string;
}
