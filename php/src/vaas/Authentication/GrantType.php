<?php

namespace VaasSdk\Authentication;

enum GrantType: string 
{
    case CLIENT_CREDENTIALS = 'client_credentials';
    case PASSWORD = 'password';
}