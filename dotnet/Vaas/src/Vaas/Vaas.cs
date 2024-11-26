using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Diagnostics;
using Vaas.Authentication;
using Vaas.Messages;
using Websocket.Client;

namespace Vaas;

public class ForSha256Options
{
    public bool UseCache { get; set; } = true;
}

public record ForFileOptions();

public record ForStreamOptions();

public record ForUrlOptions();

public interface IVaas
{
    /// <exception cref="VaasClientException">The request is malformed or cannot be completed.</exception>
    /// <exception cref="VaasServerException">The server encountered an internal error.</exception>
    /// <exception cref="T:System.Threading.Tasks.TaskCanceledException">The request failed due to timeout.</exception>
    Task<VaasVerdict> ForSha256Async(ChecksumSha256 sha256, CancellationToken cancellationToken,
        ForSha256Options? options = null);

    Task<VaasVerdict> ForFileAsync(string path, CancellationToken cancellationToken,
        ForFileOptions? options = null);

    Task<VaasVerdict> ForStreamAsync(
        Stream stream,
        CancellationToken cancellationToken,
        ForStreamOptions? options = null
    );

    Task<VaasVerdict> ForUrlAsync(Uri uri, CancellationToken cancellationToken,
        ForUrlOptions? options = null);
}

public class Vaas : IDisposable, IVaas
{
    private const int AuthenticationTimeoutInMs = 1000;

    private WebsocketClient? _client;
    private WebsocketClient AuthenticatedClient => GetAuthenticatedWebSocket();

    private readonly HttpClient _httpClient;

    // Uploads use a custom token instead of the identity provider token
    // TODO: Use the identity provider token for uploads
    private readonly HttpClient _uploadHttpClient = new();

    private string? SessionId { get; set; }
    private bool AuthenticatedErrorOccured { get; set; }

    private readonly TaskCompletionSource _authenticatedSource = new();
    private Task Authenticated => _authenticatedSource.Task;

    private readonly ConcurrentDictionary<string, TaskCompletionSource<VerdictResponse>> _verdictResponses = new();

    private readonly IAuthenticator _authenticator;
    private readonly VaasOptions _options;

    public Vaas(HttpClient httpClient, IAuthenticator authenticator, VaasOptions options)
    {
        Guard.IsNotNullOrWhiteSpace(options.Url.Host);
        _httpClient = httpClient;
        _authenticator = authenticator;
        _options = options;
        _httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue(ProductName, ProductVersion));
    }

    private const string ProductName = "Cs";

    private static string ProductVersion =>
        Assembly.GetAssembly(typeof(Vaas))?.GetName().Version?.ToString() ?? "0.0.0";

    private void HandleResponseMessage(ResponseMessage msg)
    {
        if (msg.MessageType != WebSocketMessageType.Text || msg.Text == null) return;
        var message = JsonSerializer.Deserialize<Message>(msg.Text);
        TaskCompletionSource<VerdictResponse>? tcs;
        switch (message?.Kind)
        {
            case "AuthResponse":
                var authenticationResponse = JsonSerializer.Deserialize<AuthenticationResponse>(msg.Text);
                if (authenticationResponse is { Success: true })
                {
                    AuthenticatedErrorOccured = false;
                    SessionId = authenticationResponse.SessionId;
                    _authenticatedSource.SetResult();
                }
                else
                    AuthenticatedErrorOccured = true;

                break;

            case "VerdictResponse":
                var options = new JsonSerializerOptions { Converters = { new JsonStringEnumConverter() } };
                var verdictResponse = JsonSerializer.Deserialize<VerdictResponse>(msg.Text, options);
                if (verdictResponse is not { IsValid: true })
                {
                    return;
                }

                if (!_verdictResponses.TryRemove(verdictResponse.Guid, out tcs))
                {
                    // Error: Server sent guid we are not waiting for, ignore it
                    return;
                }

                tcs.SetResult(verdictResponse);
                break;

            case "Error":
                var webSocketErrorResponse = JsonSerializer.Deserialize<WebSocketErrorMessage>(msg.Text);
                var requestId = webSocketErrorResponse?.RequestId;
                if (requestId == null || !_verdictResponses.TryRemove(requestId, out tcs))
                {
                    return;
                }

                var problemDetails = webSocketErrorResponse?.ProblemDetails;
                tcs.SetException(ProblemDetailsToException(problemDetails));
                break;
        }
    }

    private static Exception ProblemDetailsToException(ProblemDetails? problemDetails) => problemDetails?.Type switch
    {
        "VaasClientException" => new VaasClientException(problemDetails.Detail),
        _ => new VaasServerException(problemDetails?.Detail)
    };

    public async Task<VaasVerdict> ForUrlAsync(Uri uri, CancellationToken cancellationToken,
        ForUrlOptions? options = null)
    {
        var verdictResponse = await ForUrlRequestAsync(
            new VerdictRequestForUrl(uri, SessionId ?? throw new VaasInvalidStateException())
            {
                UseCache = _options.UseCache,
                UseShed = _options.UseHashLookup,
            });
        return VaasVerdict.From(verdictResponse);
    }

    public async Task<VaasVerdict> ForStreamAsync(
        Stream stream,
        CancellationToken cancellationToken,
        ForStreamOptions? options = null
    )
    {
        if (stream == null)
            throw new VaasClientException("Stream was null.");

        var verdictResponse = await ForStreamRequestAsync(
            new VerdictRequestForStream(SessionId ?? throw new InvalidOperationException())
            {
                UseCache = _options.UseCache,
                UseHashLookup = _options.UseHashLookup,
            });
        if (!verdictResponse.IsValid)
            throw new JsonException("VerdictResponse is not valid");
        if (verdictResponse.Verdict != Verdict.Unknown)
            throw new VaasServerException("Server returned verdict without receiving content.");

        if (
            string.IsNullOrWhiteSpace(verdictResponse.Url)
            || string.IsNullOrWhiteSpace(verdictResponse.UploadToken)
        )
        {
            throw new JsonException(
                "VerdictResponse missing URL or UploadToken for stream upload."
            );
        }

        var response = WaitForResponseAsync(verdictResponse.Guid);
        await UploadStream(stream, verdictResponse.Url, verdictResponse.UploadToken, cancellationToken);

        return VaasVerdict.From(await response);
    }

    private async Task UploadStream(Stream stream, string url, string token, CancellationToken cancellationToken)
    {
        using var requestContent = new StreamContent(stream);
        using var requestMessage = new HttpRequestMessage(HttpMethod.Put, url);
        requestMessage.Version = HttpVersion.Version11;
        requestMessage.VersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
        requestMessage.Content = requestContent;
        requestMessage.Headers.Authorization = new AuthenticationHeaderValue(token);

        var response = await _uploadHttpClient.SendAsync(requestMessage, cancellationToken);
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

    public async Task<VaasVerdict> ForSha256Async(ChecksumSha256 sha256, CancellationToken cancellationToken,
        ForSha256Options? options = null)
    {
        var reportUri = new Uri(_options.Url, $"/files/{sha256}/report");
        var request = new HttpRequestMessage()
        {
            RequestUri = reportUri,
            Method = HttpMethod.Get,
        };
        while (true)
        {
            var token = await _authenticator.GetTokenAsync(cancellationToken);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var response = await _httpClient.SendAsync(request, cancellationToken);
            switch (response.StatusCode)
            {
                case HttpStatusCode.OK:
                    var fileReport = await response.Content.ReadFromJsonAsync<FileReport>(cancellationToken);
                    return VaasVerdict.From(fileReport ?? throw new VaasServerException("TODO"));
                case HttpStatusCode.Accepted:
                    continue;
                default:
                    throw new NotImplementedException("Parse error here");
                    break;
            }
        }
    }

    private static void EnsureSuccess(HttpStatusCode status)
    {
        switch ((int)status)
        {
            case 401 or 403:
                throw new VaasAuthenticationException();
            case >= 400 and < 500:
                throw new VaasClientException("Client-side error");
            case >= 500 and < 600:
                throw new VaasServerException("Server-side error");
        }
    }

    public async Task<VaasVerdict> ForFileAsync(string path, CancellationToken cancellationToken,
        ForFileOptions? options = null)
    {
        var sha256 = Sha256CheckSum(path);
        var verdictResponse = await ForRequestAsync(
            new VerdictRequest(sha256, SessionId ?? throw new InvalidOperationException())
            {
                UseCache = _options.UseCache,
                UseShed = _options.UseHashLookup,
            });
        if (!verdictResponse.IsValid)
            throw new JsonException("VerdictResponse is not valid");
        if (verdictResponse.Verdict != Verdict.Unknown)
            return VaasVerdict.From(verdictResponse);
        if (string.IsNullOrWhiteSpace(verdictResponse.Url) ||
            string.IsNullOrWhiteSpace(verdictResponse.UploadToken))
        {
            throw new JsonException("VerdictResponse is not valid");
        }

        var response = WaitForResponseAsync(verdictResponse.Guid);
        await UploadFile(path, verdictResponse.Url, verdictResponse.UploadToken, cancellationToken);

        return VaasVerdict.From(await response);
    }

    private async Task UploadFile(string path, string url, string token, CancellationToken cancellationToken)
    {
        await using var fileStream = File.OpenRead(path);
        await UploadStream(fileStream, url, token, cancellationToken);
    }

    public async Task<List<VaasVerdict>> ForSha256ListAsync(IEnumerable<string> sha256List,
        CancellationToken cancellationToken)
    {
        return (await Task.WhenAll(sha256List.Select(async sha256 =>
            await ForSha256Async(new ChecksumSha256(sha256), cancellationToken)))).ToList();
    }

    public async Task<List<VaasVerdict>> ForFileListAsync(IEnumerable<string> fileList,
        CancellationToken cancellationToken)
    {
        return (await Task.WhenAll(fileList.Select(async filePath => await ForFileAsync(filePath, cancellationToken))))
            .ToList();
    }

    private async Task<VerdictResponse> ForRequestAsync(VerdictRequest verdictRequest)
    {
        var jsonString = JsonSerializer.Serialize(verdictRequest);
        AuthenticatedClient.Send(jsonString);

        return await WaitForResponseAsync(verdictRequest.Guid);
    }

    private async Task<VerdictResponse> ForStreamRequestAsync(VerdictRequestForStream verdictRequest)
    {
        var jsonString = JsonSerializer.Serialize(verdictRequest);
        AuthenticatedClient.Send(jsonString);

        return await WaitForResponseAsync(verdictRequest.Guid);
    }

    private async Task<VerdictResponse> ForUrlRequestAsync(VerdictRequestForUrl verdictRequestForUrl)
    {
        var jsonString = JsonSerializer.Serialize(verdictRequestForUrl);
        AuthenticatedClient.Send(jsonString);

        return await WaitForResponseAsync(verdictRequestForUrl.Guid);
    }

    private Task<VerdictResponse> WaitForResponseAsync(string guid)
    {
        var tcs = _verdictResponses.GetOrAdd(guid, _ => new TaskCompletionSource<VerdictResponse>());
        return tcs.Task;
    }

    public static string Sha256CheckSum(string filePath)
    {
        using var sha256 = SHA256.Create();
        using var fileStream = File.OpenRead(filePath);
        return Convert.ToHexString(sha256.ComputeHash(fileStream)).ToLower();
    }

    private static ClientWebSocket WebsocketClientFactory()
    {
        var clientWebSocket = new ClientWebSocket
        {
            Options =
            {
                KeepAliveInterval = TimeSpan.FromSeconds(20)
            }
        };
        return clientWebSocket;
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!disposing) return;

        _client?.Dispose();
        _httpClient.Dispose();
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private WebsocketClient GetAuthenticatedWebSocket()
    {
        if (_client == null)
            throw new VaasInvalidStateException();
        if (!_client.IsRunning)
            throw new VaasConnectionClosedException();
        if (SessionId == null)
        {
            if (AuthenticatedErrorOccured)
                throw new VaasAuthenticationException();
            throw new VaasInvalidStateException();
        }

        return _client;
    }
}