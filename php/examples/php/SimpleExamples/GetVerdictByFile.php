<?php

namespace VaasExamples;

use VaasSdk\Vaas;
use Exception;

include_once("./vendor/autoload.php");

const CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12345678901234567890";

function GeneratePseudoRandomString(int $numberOfCharacters): string {
    $string = "";
    for ($i=0; $i<$numberOfCharacters; $i++) {
        $string .= CHARS[rand(0,strlen(CHARS)-1)];
    }
    return $string;
}

function GenerateFileWithRandomContent($file_name, $size_in_bytes)
{  
   $data = GeneratePseudoRandomString($size_in_bytes);
   file_put_contents($file_name, $data); //writes $data in a file   
}

$vaas = new Vaas("Token");
$randomFileName = GeneratePseudoRandomString(10);
GenerateFileWithRandomContent("./${randomFileName}", 100);
try {
    fwrite(STDOUT, $vaas->ForFile("./${randomFileName}")."\n");
} finally {
    unlink($randomFileName);
}