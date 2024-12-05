using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Diagnostics;
using Vaas.Authentication;
using Vaas.Messages;

namespace Vaas;

public class ForSha256Options
{
    public bool UseCache { get; init; } = true;
    public bool UseHashLookup { get; init; } = true;

    public string? VaasRequestId { get; init; }

    public static ForSha256Options Default { get; } = new();
}

public class ForFileOptions
{
    public bool UseCache { get; init; } = true;
    public bool UseHashLookup { get; init; } = true;
    public string? VaasRequestId { get; init; }

    public static ForFileOptions Default { get; } = new();
}

public class ForStreamOptions
{
    public bool UseHashLookup { get; init; } = true;
    public string? VaasRequestId { get; init; }

    public static ForStreamOptions Default { get; } = new();
}

public record ForUrlOptions
{
    public bool UseHashLookup { get; init; } = true;
    public string? VaasRequestId { get; init; }
    public static ForUrlOptions Default { get; } = new();
}

public interface IVaas
{
    /// <exception cref="AuthenticationException">Authentication failed.</exception>
    /// <exception cref="VaasClientException">The request is malformed or cannot be completed.</exception>
    /// <exception cref="VaasServerException">The server encountered an internal error.</exception>
    /// <exception cref="T:System.Threading.Tasks.TaskCanceledException">The request failed due to timeout.</exception>
    Task<VaasVerdict> ForSha256Async(
        ChecksumSha256 sha256,
        CancellationToken cancellationToken,
        ForSha256Options? options = null
    );

    /// <exception cref="AuthenticationException">Authentication failed.</exception>
    /// <exception cref="VaasClientException">The request is malformed or cannot be completed.</exception>
    /// <exception cref="VaasServerException">The server encountered an internal error.</exception>
    /// <exception cref="T:System.Threading.Tasks.TaskCanceledException">The request failed due to timeout.</exception>
    Task<VaasVerdict> ForFileAsync(
        string path,
        CancellationToken cancellationToken,
        ForFileOptions? options = null
    );

    /// <exception cref="AuthenticationException">Authentication failed.</exception>
    /// <exception cref="VaasClientException">The request is malformed or cannot be completed.</exception>
    /// <exception cref="VaasServerException">The server encountered an internal error.</exception>
    /// <exception cref="T:System.Threading.Tasks.TaskCanceledException">The request failed due to timeout.</exception>
    Task<VaasVerdict> ForStreamAsync(
        Stream stream,
        CancellationToken cancellationToken,
        ForStreamOptions? options = null
    );

    /// <exception cref="AuthenticationException">Authentication failed.</exception>
    /// <exception cref="VaasClientException">The request is malformed or cannot be completed.</exception>
    /// <exception cref="VaasServerException">The server encountered an internal error.</exception>
    /// <exception cref="T:System.Threading.Tasks.TaskCanceledException">The request failed due to timeout.</exception>
    Task<VaasVerdict> ForUrlAsync(
        Uri uri,
        CancellationToken cancellationToken,
        ForUrlOptions? options = null
    );
}

public class Vaas : IVaas
{
    private const string ProductName = "Cs";

    private static string ProductVersion =>
        Assembly.GetAssembly(typeof(Vaas))?.GetName().Version?.ToString() ?? "0.0.0";

    private readonly HttpClient _httpClient;
    private readonly IAuthenticator _authenticator;
    private readonly VaasOptions _options;

    public Vaas(HttpClient httpClient, IAuthenticator authenticator, VaasOptions options)
    {
        Guard.IsNotNullOrWhiteSpace(options.Url.Host);
        _httpClient = httpClient;
        _authenticator = authenticator;
        _options = options;
        _httpClient.DefaultRequestHeaders.UserAgent.Add(
            new ProductInfoHeaderValue(ProductName, ProductVersion)
        );
    }

    public async Task<VaasVerdict> ForSha256Async(
        ChecksumSha256 sha256,
        CancellationToken cancellationToken,
        ForSha256Options? options = null
    )
    {
        options ??= ForSha256Options.Default;
        var reportUri = new Uri(
            _options.Url,
            $"/files/{sha256}/report?useCache={JsonSerializer.Serialize(options.UseCache)}&useHashLookup={JsonSerializer.Serialize(options.UseHashLookup)}"
        );
        var request = new HttpRequestMessage { RequestUri = reportUri, Method = HttpMethod.Get };

        while (true)
        {
            await AddRequestHeadersAsync(request, cancellationToken, options.VaasRequestId);
            var response = await _httpClient.SendAsync(request, cancellationToken);
            switch (response.StatusCode)
            {
                case HttpStatusCode.OK:
                    var fileReport = await response.Content.ReadFromJsonAsync<FileReport>(
                        cancellationToken
                    );
                    return VaasVerdict.From(fileReport ?? throw new VaasServerException("TODO"));
                case HttpStatusCode.Accepted:
                    continue;
                case HttpStatusCode.Unauthorized:
                    throw new VaasAuthenticationException();
                case HttpStatusCode.BadRequest:
                default:
                    throw await ParseVaasError(response);
            }
        }
    }

    private async Task AddRequestHeadersAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken,
        string requestId = ""
    )
    {
        var token = await _authenticator.GetTokenAsync(cancellationToken);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (!string.IsNullOrWhiteSpace(requestId))
            request.Headers.Add("tracestate", $"vaasrequestid={requestId}");
    }

    public async Task<VaasVerdict> ForFileAsync(
        string path,
        CancellationToken cancellationToken,
        ForFileOptions? options = null
    )
    {
        options ??= ForFileOptions.Default;

        var sha256 = Sha256CheckSum(path);

        var forSha256Options = new ForSha256Options
        {
            VaasRequestId = options.VaasRequestId,
            UseHashLookup = options.UseHashLookup,
            UseCache = options.UseCache,
        };

        var response = await ForSha256Async(sha256, cancellationToken, forSha256Options);

        var verdictWithoutDetection =
            response.Verdict is Verdict.Malicious or Verdict.Pup
            && string.IsNullOrEmpty(response.Detection);
        if (
            response.Verdict != Verdict.Unknown
            && !verdictWithoutDetection
            && !string.IsNullOrWhiteSpace(response.FileType)
            && !string.IsNullOrEmpty(response.MimeType)
        )
        {
            return response;
        }

        await using var stream = File.OpenRead(path);
        var forStreamOptions = new ForStreamOptions
        {
            VaasRequestId = options.VaasRequestId,
            UseHashLookup = options.UseHashLookup,
        };
        return await ForStreamAsync(stream, cancellationToken, forStreamOptions);
    }

    public async Task<VaasVerdict> ForStreamAsync(
        Stream stream,
        CancellationToken cancellationToken,
        ForStreamOptions? options = null
    )
    {
        options ??= ForStreamOptions.Default;
        var url = new Uri(
            _options.Url,
            $"/files?useHashLookup={JsonSerializer.Serialize(options.UseHashLookup)}"
        );

        var request = new HttpRequestMessage()
        {
            RequestUri = url,
            Method = HttpMethod.Post,
            Content = new StreamContent(stream),
        };
        await AddRequestHeadersAsync(request, cancellationToken, options.VaasRequestId);

        var response = await _httpClient.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
            await ParseVaasError(response);

        var fileAnalysisStarted = await response.Content.ReadFromJsonAsync<FileAnalysisStarted>(
            cancellationToken
        );

        var forSha256Options = new ForSha256Options
        {
            VaasRequestId = options.VaasRequestId,
            UseHashLookup = options.UseHashLookup,
        };

        return await ForSha256Async(
            fileAnalysisStarted.Sha256,
            cancellationToken,
            forSha256Options
        );
    }

    public async Task<VaasVerdict> ForUrlAsync(
        Uri uri,
        CancellationToken cancellationToken,
        ForUrlOptions? options = null
    )
    {
        options ??= ForUrlOptions.Default;
        var urlAnalysisUri = new Uri(_options.Url, "/urls");

        var urlAnalysisRequest = new HttpRequestMessage()
        {
            RequestUri = urlAnalysisUri,
            Method = HttpMethod.Post,
            Content = JsonContent.Create(
                new UrlAnalysisRequest { url = uri, useHashLookup = options.UseHashLookup }
            ),
        };

        await AddRequestHeadersAsync(urlAnalysisRequest, cancellationToken, options.VaasRequestId);
        var urlAnalysisResponse = await _httpClient.SendAsync(
            urlAnalysisRequest,
            cancellationToken
        );
        if (!urlAnalysisResponse.IsSuccessStatusCode)
            await ParseVaasError(urlAnalysisResponse);

        var id = (
            await urlAnalysisResponse.Content.ReadFromJsonAsync<UrlAnalysisStarted>(
                cancellationToken
            )
        )?.Id;

        while (true)
        {
            var reportUri = new Uri(_options.Url, $"/urls/{id}/report");
            var reportRequest = new HttpRequestMessage
            {
                RequestUri = reportUri,
                Method = HttpMethod.Get,
            };

            await AddRequestHeadersAsync(reportRequest, cancellationToken, options.VaasRequestId);
            var reportResponse = await _httpClient.SendAsync(reportRequest, cancellationToken);

            switch (reportResponse.StatusCode)
            {
                case HttpStatusCode.OK:
                    var urlReport = await reportResponse.Content.ReadFromJsonAsync<UrlReport>(
                        cancellationToken
                    );
                    return VaasVerdict.From(urlReport ?? throw new VaasServerException("TODO"));
                case HttpStatusCode.Accepted:
                    continue;
                default:
                    throw new NotImplementedException("Parse error here");
                    break;
            }
        }
    }

    private static Exception ProblemDetailsToException(ProblemDetails? problemDetails) =>
        problemDetails?.Type switch
        {
            "VaasClientException" => new VaasClientException(problemDetails.Detail),
            _ => new VaasServerException(problemDetails?.Detail),
        };

    private async Task UploadStream(
        Stream stream,
        string url,
        string token,
        CancellationToken cancellationToken
    )
    {
        using var requestContent = new StreamContent(stream);
        using var requestMessage = new HttpRequestMessage(HttpMethod.Put, url);
        requestMessage.Version = HttpVersion.Version11;
        requestMessage.VersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
        requestMessage.Content = requestContent;
        requestMessage.Headers.Authorization = new AuthenticationHeaderValue(token);

        var response = await _httpClient.SendAsync(requestMessage, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);
            ProblemDetails? problemDetails;
            try
            {
                problemDetails = JsonSerializer.Deserialize<ProblemDetails>(responseBody);
            }
            catch (JsonException)
            {
                throw new VaasServerException("Server did not return proper ProblemDetails");
            }

            throw ProblemDetailsToException(problemDetails);
        }
    }

    private static async Task<Exception> ParseVaasError(HttpResponseMessage response)
    {
        var responseBody = await response.Content.ReadAsStringAsync();
        try
        {
            var problemDetails = JsonSerializer.Deserialize<ProblemDetails>(responseBody);
            throw ProblemDetailsToException(problemDetails);
        }
        catch (JsonException)
        {
            throw (int)response.StatusCode switch
            {
                401 => new VaasAuthenticationException(
                    "server did not accept token from identity provider. Check if you are using the correct identity provider"
                ),
                >= 400 and <= 500 => new VaasClientException(
                    "HTTP Error: " + (int)response.StatusCode
                ),
                _ => new VaasServerException("HTTP Error: " + (int)response.StatusCode),
            };
        }
    }

    private async Task UploadFile(
        string path,
        string url,
        string token,
        CancellationToken cancellationToken
    )
    {
        await using var fileStream = File.OpenRead(path);
        await UploadStream(fileStream, url, token, cancellationToken);
    }

    // TODO: Move to ChecksumSha256
    public static string Sha256CheckSum(string filePath)
    {
        using var sha256 = SHA256.Create();
        using var fileStream = File.OpenRead(filePath);
        return Convert.ToHexString(sha256.ComputeHash(fileStream)).ToLower();
    }
}
