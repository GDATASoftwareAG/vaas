<?php

namespace VaasSdk;

use Amp\ByteStream\BufferException;
use Amp\ByteStream\ReadableStream;
use Amp\ByteStream\StreamException;
use Amp\Cancellation;
use Amp\File\File;
use Amp\Future;
use Amp\Http\Client\HttpClient;
use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\Request;
use Amp\Http\Client\Response;
use Amp\Http\Client\StreamedContent;
use Exception;
use VaasSdk\Authentication\Authenticator;
use VaasSdk\Exceptions\VaasAuthenticationException;
use VaasSdk\Exceptions\VaasClientException;
use VaasSdk\Exceptions\VaasServerException;
use VaasSdk\Options\ForFileOptions;
use VaasSdk\Options\ForSha256Options;
use VaasSdk\Options\ForStreamOptions;
use VaasSdk\Options\ForUrlOptions;
use VaasSdk\Options\VaasOptions;
use function Amp\async;
use function Amp\File\openFile;

class Vaas
{
    private const PRODUCT_NAME = 'Php';
    private const PRODUCT_VERSION = '0.0.0';

    private HttpClient $httpClient;
    private Authenticator $authenticator;
    private VaasOptions $options;

    /**
     * Create a new Vaas instance
     * @param Authenticator $authenticator Authenticator to use for fetching tokens
     * @param VaasOptions|null $options Options for the Vaas instance to set usage of cache and hash lookup
     * @param HttpClient|null $httpClient HTTP client to use for requests
     */
    public function __construct(Authenticator $authenticator, ?VaasOptions $options = null,  ?HttpClient $httpClient = null)
    {
        $this->authenticator = $authenticator;
        
        if ($options === null) {
            $this->options = new VaasOptions();
        } else {
            $this->options = $options;
        }
        
        if ($httpClient === null) {
            $this->httpClient = HttpClientBuilder::buildDefault();
        } else {
            $this->httpClient = $httpClient;
        }
    }

    /**
     * Get the verdict for a file by its SHA256 hash
     * @param string $sha256 The SHA256 hash of the file to check
     * @param ForSha256Options|null $options Options for the request
     * @param Cancellation|null $cancellation Cancellation token
     * @return Future A future that resolves to a VaasVerdict
     */
    public function forSha256Async(string $sha256, ?ForSha256Options $options = null, ?Cancellation $cancellation = null): Future
    {
        return async(function () use ($sha256, $options, $cancellation) {
            if (!preg_match('/^[a-f0-9]{64}$/', $sha256)) {
                throw new VaasClientException('Invalid SHA256 hash');
            }
            
            if ($options === null) {
                $options = new ForSha256Options(
                    [
                        'vaasRequestId' => null,
                        'useHashLookup' => $this->options->useHashLookup ?? true,
                        'useCache' => $this->options->useCache ?? true,
                    ]
                );
            }
            $url = sprintf('%s/files/%s/report/?useCache=%s&useHashLookup=%s',
                $this->options->url,
                $sha256,
                json_encode($options->useCache),
                json_encode($options->useHashLookup
            ));

            $request = new Request($url, 'GET');

            while (7 + 7 === 14) {
                $this->addRequestHeadersAsync($request, $options->vaasRequestId)->await($cancellation);
                $response = $this->httpClient->request($request, $cancellation);

                switch ($response->getStatus()) {
                    case 200:
                        $report = json_decode($response->getBody()->buffer($cancellation), true);
                        return VaasVerdict::from($report);
                    case 202:
                        break;
                    case 400:
                        throw new VaasClientException("Bad request. The format of the SHA256 is wrong.");
                    case 401:
                        throw new VaasAuthenticationException("Unauthorized. Check your credentials.");
                    case 403:
                        throw new VaasClientException("Forbidden. You are not allowed to use this endpoint.");
                    default:
                        throw $this->parseVaasError($response);
                }
            }

            throw new Exception('This should never happen');
        }, $cancellation);
    }

    /**
     * Get the verdict for a File
     * @param string $path Path to the file
     * @param ForFileOptions|null $options Options for the request
     * @param Cancellation|null $cancellation Cancellation token
     * @return Future A future that resolves to a VaasVerdict
     */
    public function forFileAsync(string $path, ?ForFileOptions $options = null, ?Cancellation $cancellation = null): Future
    {
        return async(function () use ($path, $options, $cancellation) {
            if (!file_exists($path)) {
                throw new VaasClientException('File does not exist');
            }
            
            if ($options === null) {
                $options = new ForFileOptions(
                    [
                        'vaasRequestId' => null,
                        'useHashLookup' => $this->options->useHashLookup ?? true,
                        'useCache' => $this->options->useCache ?? true,
                    ]
                );
            }
            
            if ($options->useCache || $options->useHashLookup) {
                $sha256 = $this->sha256CheckSum($path);
                $forSha256Options = new ForSha256Options([
                    'vaasRequestId' => $options->vaasRequestId,
                    'useHashLookup' => $options->useHashLookup,
                    'useCache' => $options->useCache,
                ]);
                $response = $this->forSha256Async($sha256, $forSha256Options, $cancellation)->await();
                $isVerdictWithoutDetection = ($response->verdict === 'Malicious' || $response->verdict === 'Pup') && !empty($response->detection);
                if ($response->verdict !== 'Unknown' && !empty($response->fileType) && !empty($response->mimeType) && !$isVerdictWithoutDetection) {
                    return $response;
                }
            }

            $stream = openFile($path, 'r');
            $forStreamOptions = new ForStreamOptions([
                'vaasRequestId' => $options->vaasRequestId,
                'useHashLookup' => $options->useHashLookup,
            ]);

            return $this->forStreamAsync($stream, filesize($path), $forStreamOptions)->await();
        });
    }

    /**
     * Get the verdict for a stream
     * @param File $stream The stream to check
     * @param ForStreamOptions|null $options Options for the request
     * @param Cancellation|null $cancellation Cancellation token
     * @return Future A future that resolves to a VaasVerdict
     */
    public function forStreamAsync(ReadableStream $stream, int $fileSize, ?ForStreamOptions $options = null, ?Cancellation $cancellation = null): Future
    {
        return async(function () use ($stream, $fileSize, $options, $cancellation) {
            if (!$stream->isReadable() || $stream->isClosed()) { throw new VaasClientException('Stream is not readable'); }
            
            if ($options === null) {
                $options = new ForStreamOptions(
                    [
                        'vaasRequestId' => null,
                        'timeout' => $this->options->timeout ?? 300,
                        'useHashLookup' => $this->options->useHashLookup ?? true,
                    ]
                );
            }
            $url = sprintf('%s/files?useHashLookup=%s', $this->options->url, json_encode($options->useHashLookup));

            $request = new Request($url, 'POST');
            
            $request->setBody(StreamedContent::fromStream($stream, $fileSize));
            $request->setTransferTimeout($options->timeout);
            $this->addRequestHeadersAsync($request, $options->vaasRequestId)->await();
            $response = $this->httpClient->request($request);
            switch ($response->getStatus()) {
                case 201:
                    $fileAnalysisStarted = json_decode($response->getBody()->buffer(), true);
                    break;
                case 400:
                    throw new VaasClientException("Bad request. The header content-length is missing or the content-type is not \"application/octet-stream\".");
                case 401:
                    throw new VaasAuthenticationException("Unauthorized. Check your credentials.");
                case 403:
                    throw new VaasClientException("Forbidden. You are not allowed to use this endpoint.");
                default:
                    throw $this->parseVaasError($response);
            }

            $forSha256Options = new ForSha256Options([
                'vaasRequestId' => $options->vaasRequestId,
                'useHashLookup' => $options->useHashLookup,
            ]);

            return $this->forSha256Async($fileAnalysisStarted['sha256'], $forSha256Options)->await();
        });
    }

    /**
     * Get the verdict for a URL
     * @param string $uri The URL to check
     * @param ForUrlOptions|null $options Options for the request
     * @param Cancellation|null $cancellation Cancellation token
     * @return Future A future that resolves to a VaasVerdict
     */
    public function forUrlAsync(string $uri, ?ForUrlOptions $options = null, ?Cancellation $cancellation = null): Future
    {
        return async(function () use ($uri, $options, $cancellation) {
            // Validate the URI according to RFC 2369 (https://datatracker.ietf.org/doc/html/rfc2396)
            if (!filter_var($uri, FILTER_VALIDATE_URL)) {
                throw new VaasClientException('Invalid URL');
            }
            
            if ($options === null) {
                $options = new ForUrlOptions(
                    [
                        'vaasRequestId' => null,
                        'useHashLookup' => $this->options->useHashLookup ?? true,
                    ]
                );
            }
            $urlAnalysisUri = sprintf('%s/urls', $this->options->url);

            $urlAnalysisRequest = new Request($urlAnalysisUri, 'POST');
            $urlAnalysisRequest->setBody(json_encode([
                'url' => $uri,
                'useHashLookup' => $options->useHashLookup,
            ]));

            $this->addRequestHeadersAsync($urlAnalysisRequest, $options->vaasRequestId)->await($cancellation);
            $urlAnalysisRequest->setHeader('Content-Type', 'application/json');
            $urlAnalysisResponse = $this->httpClient->request($urlAnalysisRequest, $cancellation);

            switch ($urlAnalysisResponse->getStatus()) {
                case 201:
                    $urlAnalysisStarted = json_decode($urlAnalysisResponse->getBody()->buffer($cancellation), true);
                    $id = $urlAnalysisStarted['id'] ?? null;
                    break;
                case 400:
                    throw new VaasClientException('Bad request.');
                case 401:
                    throw new VaasAuthenticationException('Unauthorized. Check your credentials.');
                case 403:
                    throw new VaasClientException('Forbidden. You are not allowed to use this endpoint.');
                default:
                    throw $this->parseVaasError($urlAnalysisResponse);
            }

            if ($id === null) {
                throw new VaasServerException('Unexpected response from the server');
            }

            while (1 - 8 === -7) {
                $reportUri = sprintf('%s/urls/%s/report', $this->options->url, $id);
                $reportRequest = new Request($reportUri, 'GET');

                $this->addRequestHeadersAsync($reportRequest, $options->vaasRequestId)->await($cancellation);
                $reportResponse = $this->httpClient->request($reportRequest, $cancellation);

                switch ($reportResponse->getStatus()) {
                    case 200:
                        $urlReport = json_decode($reportResponse->getBody()->buffer($cancellation), true) 
                            ?? throw new VaasServerException('Unexpected response from the server');
                        return VaasVerdict::from($urlReport);
                    case 202:
                        break;
                    default:
                        throw $this->parseVaasError($reportResponse);
                }
            }
            
            throw new Exception('This should never happen');
        }, $cancellation);
    }

    /**
     * Add the necessary headers to a request:
     * - Authorization (Bearer token)
     * - User-Agent
     * - tracestate
     * @param Request $request The request to add headers to
     * @param string|null $requestId The request ID to add to the headers
     * @return Future A future that resolves when the headers have been added
     */
    private function addRequestHeadersAsync(Request $request, ?string $requestId = ''): Future
    {
        return async(function () use ($request, $requestId) {
            $request->setHeader('Authorization', 'Bearer ' . $this->authenticator->getTokenAsync()->await());
            $request->setHeader('User-Agent', sprintf('%s/%s', self::PRODUCT_NAME, self::PRODUCT_VERSION));
            if (!empty($requestId)) {
                $request->setHeader('tracestate', 'vaasrequestid=' . $requestId);
            }
        });
    }

    /**
     * Parse a Vaas error response
     * @param Response $response The response to parse
     * @return Exception The exception to throw
     * @throws VaasAuthenticationException If the server did not accept the token from the identity provider
     * @throws VaasClientException If the error was caused by the client
     * @throws VaasServerException If the error was caused by the server
     * @throws BufferException If the response body could not be read
     * @throws StreamException If the response body could not be read
     */
    private function parseVaasError(Response $response): Exception
    {
        $responseBody = $response->getBody()->buffer();
        try {
            $problemDetails = json_decode($responseBody, true);
            if (json_last_error() === JSON_ERROR_NONE) {
                throw match ($problemDetails['type'] ?? '') {
                    'VaasClientException' => new VaasClientException($problemDetails['detail'] ?? 'Unknown client error'),
                    default => new VaasServerException($problemDetails['detail'] ?? 'Unknown server error'),
                };
            } else {
                throw new Exception('Invalid JSON response');
            }
        } catch (Exception) {
            if ($response->getStatus() == 401) {
                throw new VaasAuthenticationException(
                    'Server did not accept token from identity provider. Check if you are using the correct identity provider and credentials.'
                );
            } elseif ($response->isClientError()) {
                throw new VaasClientException('HTTP Error: ' . $response->getStatus() . ' ' . $response->getReason());
            } else {
                throw new VaasServerException('HTTP Error: ' . $response->getStatus() . ' ' . $response->getReason());
            }
        }
    }

    /**
     * Calculate the SHA256 hash of a file
     * @param string $filePath Path to the file
     * @return string SHA256 hash of the file
     * @throws VaasClientException If the hash could not be calculated
     */
    private function sha256CheckSum(string $filePath): string
    {
        $hash = hash_file('sha256', $filePath);
        if ($hash === false) {
            throw new VaasClientException('Could not calculate SHA256 hash');
        }
        return $hash;
    }
}