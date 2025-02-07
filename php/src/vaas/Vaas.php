<?php

namespace VaasSdk;

use Amp\ByteStream\ReadableStream;
use Amp\Cancellation;
use Amp\File\FilesystemException;
use Amp\Future;
use Amp\Http\Client\HttpClient;
use Amp\Http\Client\HttpException;
use Amp\Http\Client\Request;
use Amp\Http\Client\Response;
use Amp\Http\Client\StreamedContent;
use Exception;
use Psr\Log\LoggerInterface;
use VaasSdk\Authentication\AuthenticatorInterface;
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
    private AuthenticatorInterface $authenticator;
    private VaasOptions $options;
    private LoggerInterface $logger;
    
    private function __construct() {}

    public static function builder(): VaasBuilder {
        return new VaasBuilder();
    }

    public static function createInstance(): Vaas {
        return new self();
    }

    public function withOptions(VaasOptions $options): self
    {
        $this->options = $options;
        return $this;
    }

    public function withHttpClient(HttpClient $httpClient): self
    {
        $this->httpClient = $httpClient;
        return $this;
    }

    public function withAuthenticator(AuthenticatorInterface $authenticator): self
    {
        $this->authenticator = $authenticator;
        return $this;
    }

    public function withLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;
        return $this;
    }

    /**
     * Get the verdict for a file by its SHA256 hash
     * @param Sha256 $sha256 The SHA256 hash of the file to check
     * @param ForSha256Options|null $options Options for the request
     * @param Cancellation|null $cancellation Cancellation token
     * @return Future A future that resolves to a VaasVerdict
     * @throws HttpException If the request fails
     * @throws VaasClientException The request is malformed or cannot be completed. Recommended actions: Don't repeat the request. Log. Analyze the error.
     * @throws VaasAuthenticationException The Vaas authentication failed. Recommended actions: Double-check your credentials in the authenticator object. Check if your authenticator connects to the correct token endpoint. Check if the token endpoint is reachable. If your problem persists contact G DATA.
     * @throws VaasServerException The server encountered an internal error. Recommended actions: You may retry the request after a certain delay. If the problem persists contact G DATA.
     */
    public function forSha256Async(Sha256 $sha256, ?ForSha256Options $options = null, ?Cancellation $cancellation = null): Future
    {
        return async(function () use ($sha256, $options, $cancellation) {
            $this->logger->debug("Requesting verdict for SHA256: $sha256");

            $options = $options ?? ForSha256Options::fromVaasOptions($this->options);

            $url = sprintf('%s/files/%s/report/?useCache=%s&useHashLookup=%s',
                $this->options->vaasUrl,
                $sha256,
                json_encode($options->useCache),
                json_encode($options->useHashLookup
            ));

            while (true) {
                $request = new Request($url, 'GET');
                $this->enrichRequestAsync($request,$this->options->timeout, $options->vaasRequestId)->await($cancellation);
                $this->logger->debug("Send request for SHA256: " . self::logUri($request));
                $response = $this->httpClient->request($request, $cancellation);

                switch ($response->getStatus()) {
                    case 200:
                        $report = json_decode($response->getBody()->buffer($cancellation), true);
                        $verdict = VaasVerdict::from($report);
                        $this->logger->info("Received verdict for $sha256: $verdict");
                        return $verdict;
                    case 202:
                        $this->logger->debug("Verdict for $sha256 is not ready yet, retrying...");
                        break;
                    case 400:
                        $this->logger->error("Bad request for SHA256: $sha256");
                        throw new VaasClientException("Bad request. The format of the SHA256 is wrong.");
                    case 401:
                        $this->logger->error("Unauthorized request for SHA256: $sha256");
                        throw new VaasAuthenticationException("Unauthorized. Check your credentials.");
                    case 403:
                        $this->logger->error("Forbidden request for SHA256: $sha256");
                        throw new VaasClientException("Forbidden. You are not allowed to use this endpoint.");
                    default:
                        $this->logger->error("Error requesting verdict for SHA256: $sha256");
                        throw $this->parseVaasError($response);
                }
            }
        }, $cancellation);
    }

    /**
     * Get the verdict for a File
     * @param string $path Path to the file
     * @param ForFileOptions|null $options Options for the request
     * @param Cancellation|null $cancellation Cancellation token
     * @return Future A future that resolves to a VaasVerdict
     * @throws VaasClientException The request is malformed or cannot be completed. Recommended actions: Don't repeat the request. Log. Analyze the error.
     * @throws VaasAuthenticationException The Vaas authentication failed. Recommended actions: Double-check your credentials in the authenticator object. Check if your authenticator connects to the correct token endpoint. Check if the token endpoint is reachable. If your problem persists contact G DATA.
     * @throws VaasServerException The server encountered an internal error. Recommended actions: You may retry the request after a certain delay. If the problem persists contact G DATA.
     */
    public function forFileAsync(string $path, ?ForFileOptions $options = null, ?Cancellation $cancellation = null): Future
    {
        return async(function () use ($path, $options, $cancellation) {
            $this->logger->debug("Requesting verdict for file: $path");

            if (!file_exists($path)) {
                $this->logger->error("File does not exist: $path");
                throw new VaasClientException('File does not exist');
            }

            $options = $options ?? ForFileOptions::fromVaasOptions($this->options);

            if ($options->useCache || $options->useHashLookup) {
                $forSha256Options = new ForSha256Options(
                    $options->useCache, $options->useHashLookup, $options->vaasRequestId);
                $sha256 = Sha256::TryFromFile($path)->await();
                $this->logger->debug("Check if file $path is already known by its SHA256: $sha256");
                try {
                    $response = $this->forSha256Async($sha256, $forSha256Options, $cancellation)->await();
                    $isVerdictWithoutDetection = ($response->verdict === 'Malicious' || $response->verdict === 'Pup') && !empty($response->detection);
                    if ($response->verdict !== 'Unknown' && !empty($response->fileType) && !empty($response->mimeType) && !$isVerdictWithoutDetection) {
                        $this->logger->debug("File $path is already known from cache or G DATA cloud by its SHA256: $sha256");
                        return $response;
                    }
                }
                catch (Exception $ex) {
                    $this->logger->debug("Something went wrong while checking the SHA256 of file $path: " . $ex->getMessage());
                }
            }

            try {
                $stream = openFile($path, 'r');
                $cancellation?->subscribe(function () use ($stream) { $stream->close(); });
                $forStreamOptions = new ForStreamOptions($options->useHashLookup, $options->timeout, $options->vaasRequestId);
                $this->logger->debug("Requesting verdict for $path as file stream");
                return $this->forStreamAsync($stream, filesize($path), $forStreamOptions)->await();
            } catch (FilesystemException  $ex) {
                $this->logger->error("Error opening file: $path");
                throw new VaasClientException('Error opening file (' . $path . '): ' . $ex->getMessage());
            } catch (Exception $ex){
                $this->logger->error("Error requesting verdict for file '$path': " . $ex->getMessage());
                throw $ex;
            }
            finally {
                if (isset($stream)) {
                    $stream->close();
                }
            }
        });
    }

    /**
     * Get the verdict for a stream
     * @param ReadableStream $stream The stream to check
     * @param int $fileSize The size of the file in bytes
     * @param ForStreamOptions|null $options Options for the request
     * @param Cancellation|null $cancellation Cancellation token
     * @return Future A future that resolves to a VaasVerdict
     * @throws HttpException If the request fails
     * @throws VaasClientException The request is malformed or cannot be completed. Recommended actions: Don't repeat the request. Log. Analyze the error.
     * @throws VaasAuthenticationException The Vaas authentication failed. Recommended actions: Double-check your credentials in the authenticator object. Check if your authenticator connects to the correct token endpoint. Check if the token endpoint is reachable. If your problem persists contact G DATA.
     * @throws VaasServerException The server encountered an internal error. Recommended actions: You may retry the request after a certain delay. If the problem persists contact G DATA.
     */
    public function forStreamAsync(ReadableStream $stream, int $fileSize, ?ForStreamOptions $options = null, ?Cancellation $cancellation = null): Future
    {
        return async(function () use ($stream, $fileSize, $options, $cancellation) {
            try {
                $this->logger->debug("Requesting verdict for stream");

                if (!$stream->isReadable() || $stream->isClosed()) {
                    $this->logger->error("Stream is not readable");
                    throw new VaasClientException('Stream is not readable');
                }

                $options = $options ?? ForStreamOptions::fromVaasOptions($this->options);
                
                $url = sprintf('%s/files?useHashLookup=%s', $this->options->vaasUrl, json_encode($options->useHashLookup));

                $request = new Request($url, 'POST');

                $request->setBody(StreamedContent::fromStream($stream, $fileSize));
                $this->enrichRequestAsync($request, $options->timeout, $options->vaasRequestId)->await();
                $this->logger->debug("Send request for file stream: " . self::logUri($request));
                $response = $this->httpClient->request($request, $cancellation);
            } finally {
                $stream->close();
            }
            switch ($response->getStatus()) {
                case 201:
                    try {
                        $fileAnalysisStarted = json_decode($response->getBody()->buffer(), true);
                    } catch (Exception $ex) {
                        $this->logger->error("Error parsing response for stream: " . $ex->getMessage());
                        throw new VaasServerException('Error parsing response stream', $ex->getCode(), $ex);
                    }
                    $this->logger->debug("File uploaded successfully and analysis started");
                    break;
                case 400:
                    $this->logger->error("Bad request for stream");
                    throw new VaasClientException("Bad request. The header content-length is missing or the content-type is not \"application/octet-stream\".");
                case 401:
                    $this->logger->error("Unauthorized request for stream");
                    throw new VaasAuthenticationException("Unauthorized. Check your credentials.");
                case 403:
                    $this->logger->error("Forbidden request for stream");
                    throw new VaasClientException("Forbidden. You are not allowed to use this endpoint.");
                default:
                    $this->logger->error("Error requesting verdict for stream");
                    throw $this->parseVaasError($response);
            }

            $forSha256Options = new ForSha256Options(true, $options->useHashLookup, $options->vaasRequestId);

            if (!isset($fileAnalysisStarted['sha256'])) {
                $this->logger->error("Unexpected response from the server for stream");
                throw new VaasServerException('Unexpected response from the server');
            }
            $sha256 = Sha256::TryFromString($fileAnalysisStarted['sha256'])->await();

            $this->logger->debug("Requesting verdict for uploaded file with SHA256: $sha256");
            return $this->forSha256Async($sha256, $forSha256Options)->await();
        });
    }

    /**
     * Get the verdict for a URL
     * @param string $uri The URL to check
     * @param ForUrlOptions|null $options Options for the request
     * @param Cancellation|null $cancellation Cancellation token
     * @return Future A future that resolves to a VaasVerdict
     * @throws HttpException If the request fails
     * @throws VaasClientException The request is malformed or cannot be completed. Recommended actions: Don't repeat the request. Log. Analyze the error.
     * @throws VaasAuthenticationException The Vaas authentication failed. Recommended actions: Double-check your credentials in the authenticator object. Check if your authenticator connects to the correct token endpoint. Check if the token endpoint is reachable. If your problem persists contact G DATA.
     * @throws VaasServerException The server encountered an internal error. Recommended actions: You may retry the request after a certain delay. If the problem persists contact G DATA.
     */
    public function forUrlAsync(string $uri, ?ForUrlOptions $options = null, ?Cancellation $cancellation = null): Future
    {
        return async(function () use ($uri, $options, $cancellation) {
            $this->logger->debug("Requesting verdict for URL: $uri");
            $uri = Vaas::validUri($uri);

            $options = $options ?? ForUrlOptions::fromVaasOptions($this->options);

            $urlAnalysisUri = sprintf('%s/urls', $this->options->vaasUrl);

            $urlAnalysisRequest = new Request($urlAnalysisUri, 'POST');
            $urlAnalysisRequest->setBody(json_encode([
                'url' => $uri,
                'useHashLookup' => $options->useHashLookup,
            ]));

            $this->enrichRequestAsync($urlAnalysisRequest, $options->timeout, $options->vaasRequestId)->await($cancellation);
            $urlAnalysisRequest->setHeader('Content-Type', 'application/json');
            $this->logger->debug("Send request for url analysis: " . self::logUri($urlAnalysisRequest));
            $urlAnalysisResponse = $this->httpClient->request($urlAnalysisRequest, $cancellation);

            switch ($urlAnalysisResponse->getStatus()) {
                case 201:
                    try {
                        $urlAnalysisStarted = json_decode($urlAnalysisResponse->getBody()->buffer($cancellation), true);
                        $id = $urlAnalysisStarted['id'] ?? null;
                    } catch (Exception $ex) {
                        $this->logger->error("Error parsing response for URL: $uri");
                        throw new VaasServerException('Error parsing response from VaaS backend for URL scan', $ex->getCode(), $ex);
                    }                    
                    $this->logger->debug("URL analysis for " . $uri . " started with id: " . $id);
                    break;
                case 400:
                    $this->logger->error("Bad request for URL: $uri");
                    throw new VaasClientException('Bad request.');
                case 401:
                    $this->logger->error("Unauthorized request for URL: $uri");
                    throw new VaasAuthenticationException('Unauthorized. Check your credentials.');
                case 403:
                    $this->logger->error("Forbidden request for URL: $uri");
                    throw new VaasClientException('Forbidden. You are not allowed to use this endpoint.');
                default:
                    $this->logger->error("Error requesting verdict for URL: $uri");
                    throw $this->parseVaasError($urlAnalysisResponse);
            }

            if ($id === null) {
                $this->logger->error("Unexpected response from the server for URL: $uri");
                throw new VaasServerException('Unexpected response from the server');
            }

            while (true) {
                $reportUri = sprintf('%s/urls/%s/report', $this->options->vaasUrl, $id);
                $reportRequest = new Request($reportUri, 'GET');

                $this->enrichRequestAsync($reportRequest, $options->timeout, $options->vaasRequestId)->await($cancellation);
                $reportResponse = $this->httpClient->request($reportRequest, $cancellation);

                switch ($reportResponse->getStatus()) {
                    case 200:
                        try {
                            $urlReport = json_decode($reportResponse->getBody()->buffer($cancellation), true)
                                ?? throw new VaasServerException('Unexpected response from the server');
                            $verdict = VaasVerdict::from($urlReport);
                            $this->logger->info("Received verdict for $uri: $verdict");
                            return $verdict;
                        } catch (Exception $ex) {
                            $this->logger->error("Error parsing response for URL scan: " . $ex->getMessage());
                            throw new VaasServerException('Error parsing response from VaaS backend for URL scan', $ex->getCode(), $ex);
                        }
                    case 202:
                        $this->logger->debug("Verdict for URL: $uri is not ready yet, retrying...");
                        break;
                    default:
                        $this->logger->error("Error requesting verdict for URL: $uri");
                        throw $this->parseVaasError($reportResponse);
                }
            }
        }, $cancellation);
    }

    /**
     * Set necessary headers to a request:
     * - Authorization (Bearer token)
     * - User-Agent
     * - tracestate
     * Also set the timeout for the request.
     * @param Request $request The request to add headers to
     * @param int $timeout The timeout to set for the request
     * @param string|null $requestId The request ID to add to the headers
     * @return Future A future that resolves when the headers have been added
     */
    private function enrichRequestAsync(Request $request, int $timeout, ?string $requestId = ''): Future
    {
        return async(function () use ($request, $requestId, $timeout) {
            $this->logger->debug("Add request headers");
            $request->setHeader('Authorization', 'Bearer ' . $this->authenticator->getTokenAsync()->await());
            $this->logger->debug("Successfully added authorization header with bearer token");
            $request->setHeader('User-Agent', sprintf('%s/%s', self::PRODUCT_NAME, self::PRODUCT_VERSION));
            if (!empty($requestId)) {
                $request->setHeader('tracestate', 'vaasrequestid=' . $requestId);
                $this->logger->debug("Request ID added to headers: $requestId");
            }
            $request->setTransferTimeout($timeout);
            $request->setInactivityTimeout($timeout);
            $this->logger->debug("Timeout set to " . $timeout . " seconds");
        });
    }

    /**
     * Parse a Vaas error response
     * @param Response $response The response to parse
     * @return Exception The exception to throw
     * @throws VaasAuthenticationException If the server did not accept the token from the identity provider
     * @throws VaasClientException If the error was caused by the client
     * @throws VaasServerException If the error was caused by the server
     */
    private function parseVaasError(Response $response): Exception
    {
        try {
            $responseBody = $response->getBody()->buffer();
            $problemDetails = json_decode($responseBody, true);
            if (json_last_error() === JSON_ERROR_NONE) {
                throw match ($problemDetails['type'] ?? '') {
                    'VaasClientException' => new VaasClientException($problemDetails['detail'] ?? 'Unknown client error'),
                    default => new VaasServerException($problemDetails['detail'] ?? 'Unknown server error'),
                };
            } else {
                throw new VaasServerException('Invalid JSON error response from VaaS backend');
            }
        } catch (Exception) {
            if ($response->getStatus() == 401) {
                throw new VaasAuthenticationException(
                    'Server did not accept token from identity provider. Check if you are using the correct identity provider and credentials.'
                );
            } elseif ($response->isClientError()) {
                throw new VaasClientException('HTTP Error: ' . $response->getStatus() . ' ' . $response->getReason());
            }
            throw new VaasServerException('HTTP Error: ' . $response->getStatus() . ' ' . $response->getReason());
        }
    }
    
    private static function logUri(Request $request): string
    {
        $uri = $request->getUri()->getScheme() . '://' . $request->getUri()->getHost() . $request->getUri()->getPort() . $request->getUri()->getPath();
        $query = $request->getUri()->getQuery();
        $fragment = $request->getUri()->getFragment();
        return $uri . (!empty($query) ? '?' . $query : '') . (!empty($fragment) ? '#' . $fragment : '');
    }

    /**
     * Validate the URI per RFC 2396 (https://datatracker.ietf.org/doc/html/rfc2396)
     * @param string $uri The URI to validate
     * @return string The validated URI
     * @throws VaasClientException If the URI is invalid
     */
    public static function validUri(string $uri): string
    {
        if (!filter_var($uri, FILTER_VALIDATE_URL)) {
            throw new VaasClientException('Invalid URI');
        }
        return $uri;
    }
}