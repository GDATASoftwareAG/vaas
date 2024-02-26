<?php

namespace VaasSdk\Message;

enum Kind: string
{
    case AuthRequest = "AuthRequest";
    case AuthResponse = "AuthResponse";
    case VerdictRequest = "VerdictRequest";
    case VerdictResponse = "VerdictResponse";
    case VerdictRequestForUrl = "VerdictRequestForUrl";
    case VerdictRequestForStream = "VerdictRequestForStream";
    case Error = "Error";
}
