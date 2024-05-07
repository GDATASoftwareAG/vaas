<?php

namespace VaasSdk;

use Amp\Future;
use Amp\Http\Client\HttpClient;
use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\HttpContent;
use Amp\Http\Client\HttpException;
use Amp\Http\Client\Request;
use Amp\Http\Client\StreamedContent;
use Amp\Websocket\WebsocketClosedException;
use InvalidArgumentException;
use JsonMapper_Exception;
use VaasSdk\Exceptions\FileDoesNotExistException;
use VaasSdk\Exceptions\InvalidSha256Exception;
use VaasSdk\Exceptions\UploadFailedException;
use VaasSdk\Exceptions\VaasServerException;
use VaasSdk\Message\Verdict;
use VaasSdk\Message\VerdictRequest;
use VaasSdk\Message\VerdictRequestForStream;
use VaasSdk\Message\VerdictResponse;
use VaasSdk\Message\VerdictRequestForUrl;
use VaasSdk\VaasOptions;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use VaasSdk\Message\VaasVerdict;

class Vaas
{
    private string $_vaasUrl = "wss://gateway.production.vaas.gdatasecurity.de";
    private VaasWebSocket $_vaasWebSocket;
    private LoggerInterface $_logger;
    private HttpClient $_httpClient;
    private VaasOptions $_options;

    /**
     */
    public function __construct(?string $vaasUrl, ?LoggerInterface $logger = null, AuthenticatorInterface $authenticator, VaasOptions $options = new VaasOptions())
    {
        $this->_options = $options;
        $this->_httpClient = HttpClientBuilder::buildDefault();
        if ($logger != null)
            $this->_logger = $logger;
        else
            $this->_logger = new NullLogger();
        $this->_logger->debug("Url: " . $vaasUrl);
        if ($vaasUrl)
            $this->_vaasUrl = $vaasUrl;
        $this->_vaasWebSocket = new VaasWebSocket($this->_vaasUrl, $authenticator);
    }

    /**
     * Gets verdict for SHA256
     *
     * @param string $hashString the hash to get the verdict for
     * @param string|null $uuid unique identifier
     *
     * @return VaasVerdict the verdict
     * @throws InvalidSha256Exception
     * @throws WebsocketClosedException
     */
    public function ForSha256(string $hashString, string $uuid = null): VaasVerdict
    {
        $this->_logger->debug("ForSha256WithFlags", ["Sha256" => $hashString]);

        return
            new VaasVerdict($this->_verdictResponseForSha256(
                $hashString,
                $uuid
            )->await());
    }

    /**
     * Gets verdict by url
     *
     * @param string $url url to get the verdict for
     * @param string|null $uuid unique identifier
     *
     * @return VaasVerdict the verdict
     * @throws InvalidArgumentException
     * @throws WebsocketClosedException
     */
    public function ForUrl(string $url, string $uuid = null): VaasVerdict
    {
        $this->_logger->debug("ForUrlWithFlags", ["URL:" => $url]);

        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            throw new InvalidArgumentException("Url is not valid");
        }

        return new VaasVerdict($this->_verdictResponseForUrl(
            $url,
            $uuid
        )->await());
    }

    /**
     * Gets verdict by file
     *
     * @param string $path the path to get the verdict for
     * @param bool $upload should the file be uploaded if initial verdict is unknown
     * @param string|null $uuid unique identifier
     *
     * @return VaasVerdict the verdict
     * @throws FileDoesNotExistException
     * @throws InvalidSha256Exception
     * @throws UploadFailedException
     * @throws HttpException
     * @throws WebsocketClosedException
     */
    public function ForFile(string $path, bool $upload = true, string $uuid = null): VaasVerdict
    {
        $this->_logger->debug("ForFileWithFlags", ["File" => $path]);

        $sha256 = Sha256::TryFromFile($path);
        $this->_logger->debug("Calculated Hash", ["Sha256" => $sha256]);

        $verdictResponse = $this->_verdictResponseForSha256($sha256, $uuid)->await();
        if ($verdictResponse->verdict == Verdict::UNKNOWN && $upload === true) {
            $stream = StreamedContent::fromFile($path);
            $futureVerdictResponse = $this->_vaasWebSocket->waitForVerdict($verdictResponse->guid);
            $this->UploadStream($stream, $verdictResponse->url, $verdictResponse->upload_token);
            $verdictResponse = $futureVerdictResponse->await();
            return new VaasVerdict($verdictResponse);
        }

        return new VaasVerdict($verdictResponse);
    }

    /**
     * Gets verdict by stream
     *
     * @param HttpContent $stream
     * @param string|null $uuid unique identifier
     *
     * @return VaasVerdict
     * @throws HttpException
     * @throws JsonMapper_Exception
     * @throws UploadFailedException
     * @throws VaasServerException
     * @throws WebsocketClosedException
     */
    public function ForStream(HttpContent $stream, string $uuid = null): VaasVerdict
    {
        $verdictResponse = $this->_verdictResponseForStream($uuid)->await();

        if ($verdictResponse->verdict != Verdict::UNKNOWN) {
            throw new VaasServerException("Server returned verdict without receiving content.");
        }
        if ($verdictResponse->upload_token == null || $verdictResponse->upload_token == "") {
            throw new JsonMapper_Exception("VerdictResponse missing UploadToken for stream upload.");
        }
        if ($verdictResponse->url == null || $verdictResponse->url == "") {
            throw new JsonMapper_Exception("VerdictResponse missing URL for stream upload.");
        }

        $futureVerdictResponse = $this->_vaasWebSocket->waitForVerdict($verdictResponse->guid);

        $this->UploadStream($stream, $verdictResponse->url, $verdictResponse->upload_token);

        $verdictResponse = $futureVerdictResponse->await();

        return new VaasVerdict($verdictResponse);
    }

    /**
     * @param string $hashString
     * @param string|null $uuid
     * @return Future<VerdictResponse>
     * @throws InvalidSha256Exception
     * @throws WebsocketClosedException
     */
    private function _verdictResponseForSha256(string $hashString, string $uuid = null): Future
    {
        $this->_logger->debug("_verdictResponseForSha256");
        $sha256 = Sha256::TryFromString($hashString);

        $request = new VerdictRequest(strtolower($sha256), $uuid);
        $request->use_cache = $this->_options->UseCache;
        $request->use_hash_lookup = $this->_options->UseHashLookup;
        return $this->_vaasWebSocket->sendRequest($request);
    }

    /**
     * @param string $url
     * @param string|null $uuid
     * @return Future<VerdictResponse>
     * @throws WebsocketClosedException
     */
    private function _verdictResponseForUrl(string $url, string $uuid = null): Future
    {
        $this->_logger->debug("_verdictResponseForUrl");

        $request = new VerdictRequestForUrl($url, $uuid);
        $request->use_cache = $this->_options->UseCache;
        $request->use_hash_lookup = $this->_options->UseHashLookup;
        return $this->_vaasWebSocket->sendRequest($request);
    }

    /**
     * @param string|null $uuid
     * @return Future<VerdictResponse>
     * @throws WebsocketClosedException
     */
    private function _verdictResponseForStream(string $uuid = null): Future
    {
        $this->_logger->debug("_verdictResponseForStream");

        $request = new VerdictRequestForStream($uuid);
        $request->use_cache = $this->_options->UseCache;
        $request->use_hash_lookup = $this->_options->UseHashLookup;
        return $this->_vaasWebSocket->sendRequest($request);
    }

    /**
     * @throws UploadFailedException|HttpException
     */
    private function UploadStream(HttpContent $stream, string $url, string $uploadToken): void
    {
        $request = new Request($url, "PUT", body: $stream);
        $request->addHeader("Authorization", $uploadToken);
        $response = $this->_httpClient->request($request);
        if ($response->getStatus() > 399) {
            throw new UploadFailedException($response->getReason(), $response->getStatus());
        }
    }
}
