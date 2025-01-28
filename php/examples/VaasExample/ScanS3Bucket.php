<?php

namespace VaasExamples;

use Aws\Credentials\Credentials;
use Aws\Signature\SignatureV4;
use Dotenv\Dotenv;
use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Request;
use SimpleXMLElement;
use VaasSdk\Authentication\ClientCredentialsGrantAuthenticator;
use VaasSdk\Exceptions\VaasClientException;
use VaasSdk\Options\VaasOptions;
use VaasSdk\Vaas;

include_once("./vendor/autoload.php");

$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

$CLIENT_ID = getenv("CLIENT_ID");
$CLIENT_SECRET = getenv("CLIENT_SECRET");
$VAAS_URL = getenv("VAAS_URL");
$TOKEN_URL = getenv("TOKEN_URL");
$S3_ACCESS_KEY = getenv("S3_ACCESS_KEY");
$S3_SECRET_KEY = getenv("S3_SECRET_KEY");
$S3_URL = getenv("S3_URL");
$S3_BUCKET = getenv("S3_BUCKET");
$S3_REGION = getenv("S3_REGION");

// Build VaaS
$authenticator = new ClientCredentialsGrantAuthenticator(
    clientId: $CLIENT_ID,
    clientSecret: $CLIENT_SECRET,
    tokenUrl: $TOKEN_URL
);
$vaasOptions = new VaasOptions(
    useHashLookup: true,
    useCache: false,
    vaasUrl: $VAAS_URL,
    timeout: 300
);
try {
    $vaas = Vaas::builder()
        ->withOptions($vaasOptions)
        ->withAuthenticator($authenticator)
        ->build();
} catch (VaasClientException $e) {
    fwrite(STDERR, "Error: " . $e->getMessage() . "\n");
    exit(1);
}

// List S3 bucket
$client = new Client();
$request = new Request("GET", "$S3_URL/$S3_BUCKET?list-type=2");
$credentials = new Credentials($S3_ACCESS_KEY, $S3_SECRET_KEY);
$signer = new SignatureV4("s3", $S3_REGION);
$signedRequest = $signer->signRequest($request, $credentials);
$keys = [];
try {
    $response = $client->send($signedRequest);
    $xml = new SimpleXMLElement($response->getBody()->getContents());
    foreach ($xml->Contents as $content) {
        $keys[] = (string)$content->Key;
    }
} catch (GuzzleException $e) {
    fwrite(STDERR, "Error: " . $e->getMessage() . "\n");
    exit(1);
} catch (Exception $e) {
    fwrite(STDERR, "Error: " . $e->getMessage() . "\n");
    exit(1);
}

// Iterate over everything in S3 bucket and scan with VaaS
$results = [];
$progress = 0;
$count = count($keys);
$startTimeTotal = microtime(true);
foreach ($keys as $key){
    // Pretty print progress
    $progress++;
    $percentageDone = number_format($progress / $count * 100, 1) . "%";
    echo chr(27).chr(91).'H'.chr(27).chr(91).'J';
    echo "\nProgress: $percentageDone [";
    $done = $progress / $count * 30;
    for ($i = 0; $i < 30; $i++) {
        echo $i < $done ? "=" : " ";
    }
    echo "]\n";
    echo "Execution time: " . number_format(microtime(true) - $startTimeTotal, 3) . "s\n";
    echo "Current key: $key\n\n";

    // Download file from S3 to temp file
    $request = new Request("GET", "$S3_URL/$S3_BUCKET/$key");
    $request->withHeader("Accept", "application/octet-stream");
    $credentials = new Credentials($S3_ACCESS_KEY, $S3_SECRET_KEY);
    $signer = new SignatureV4("s3", $S3_REGION);
    $signedRequest = $signer->signRequest($request, $credentials);
    try {
        $response = $client->send($signedRequest);
    } catch (GuzzleException $e) {
        fwrite(STDERR, "Error: " . $e->getMessage() . "\n");
        exit(1);
    }
    $sample = tempnam(sys_get_temp_dir(), "vaas-sample-");
    $handle = fopen($sample, "w");
    fwrite($handle, $response->getBody());
    fclose($handle);

    // Scan file with VaaS and track time
    $startTime = microtime(true);
    $vaasVerdict = $vaas->forFileAsync($sample)->await();
    $endTime = microtime(true);
    $executionTime = ($endTime - $startTime) * 1000;

    // Save VaaS verdict and execution time
    $results[] = [
        "key" => $key,
        "executionTimeInMs" => number_format($executionTime, 3),
        "verdict" => [
            "sha256" => $vaasVerdict->sha256,
            "verdict" => $vaasVerdict->verdict->value,
            "detection" => $vaasVerdict->detection,
            "fileType" => $vaasVerdict->fileType,
            "mimeType" => $vaasVerdict->mimeType
        ]
    ];

    // Delete temp file
    unlink($sample);
}

$endTimeTotal = microtime(true);
$executionTime = number_format($endTimeTotal - $startTimeTotal, 3);

file_put_contents("results-$S3_BUCKET.json", json_encode($results, JSON_PRETTY_PRINT));

echo "Results written to results.json\n";
echo "Total execution time: " . $executionTime . "s\n";
