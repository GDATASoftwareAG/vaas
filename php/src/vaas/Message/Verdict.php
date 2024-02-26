<?php

namespace VaasSdk\Message;

enum Verdict: string
{
    case MALICIOUS = "Malicious";
    case CLEAN = "Clean";
    case UNKNOWN = "Unknown";
    case PUP = "Pup";
}
