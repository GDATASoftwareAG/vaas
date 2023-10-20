using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.WebSockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Vaas.Messages;
using Websocket.Client;
using Websocket.Client.Exceptions;

namespace Vaas;

public class ForSha256Options
{
    public bool UseCache { get; set; } = true;

    public static ForSha256Options Default { get; } = new();
}

public interface IVaas
{
    Task Connect(string token);
    Task<VaasVerdict> ForUrlAsync(Uri uri, CancellationToken cancellationToken,
        Dictionary<string, string>? verdictRequestAttributes = null);
    Task<VaasVerdict> ForSha256Async(ChecksumSha256 sha256, CancellationToken cancellationToken, ForSha256Options? options = null);
    Task<VaasVerdict> ForFileAsync(string path, CancellationToken cancellationToken,
        Dictionary<string, string>? verdictRequestAttributes = null);
}

public class Vaas : IDisposable, IVaas
{
    private const int AuthenticationTimeoutInMs = 1000;

    private WebsocketClient? _client;
    private WebsocketClient AuthenticatedClient => GetAuthenticatedWebSocket();

    private readonly HttpClient _httpClient = new();

    private string? SessionId { get; set; }
    private bool AuthenticatedErrorOccured { get; set; }

    private readonly TaskCompletionSource _authenticatedSource = new();
    private Task Authenticated => _authenticatedSource.Task;

    private readonly ConcurrentDictionary<string, TaskCompletionSource<VerdictResponse>> _verdictResponses = new();

    private readonly VaasOptions _options;

    public Vaas(VaasOptions? options = null)
    {
        _options = options ?? VaasOptions.Defaults;
        _httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue(ProductName, ProductVersion));
    }

    private const string ProductName = "VaaS C# SDK";
    private static string ProductVersion => Assembly.GetAssembly(typeof(Vaas))?.GetName().Version?.ToString() ?? "0.0.0";
    
    public async Task Connect(string token)
    {
        _client = new WebsocketClient(_options.Url, WebsocketClientFactory);
        _client.ReconnectTimeout = null;
        _client.MessageReceived.Subscribe(HandleResponseMessage);
        await _client.Start();
        if (!_client.IsStarted)
        {
            throw new WebsocketException("Could not start client");
        }

        await Authenticate(token);
    }

    private void HandleResponseMessage(ResponseMessage msg)
    {
        if (msg.MessageType != WebSocketMessageType.Text) return;
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
        _=> new VaasServerException(problemDetails?.Detail)
    };
    
    private async Task Authenticate(string token)
    {
        var authenticationRequest = new AuthenticationRequest(token);
        var jsonString = JsonSerializer.Serialize(authenticationRequest);
        _client?.Send(jsonString);

        var delay = Task.Delay(AuthenticationTimeoutInMs);
        if (await Task.WhenAny(Authenticated, delay) == delay)
        {
            throw new VaasAuthenticationException();
        }
    }

    public async Task<VaasVerdict> ForUrlAsync(Uri uri, CancellationToken cancellationToken, Dictionary<string, string>? verdictRequestAttributes = null)
    {
        var verdictResponse = await ForUrlRequestAsync(new VerdictRequestForUrl(uri, SessionId ?? throw new VaasInvalidStateException())
        {
            UseCache = _options.UseCache,
            UseShed = _options.UseHashLookup,
            VerdictRequestAttributes = verdictRequestAttributes
        });
        return new VaasVerdict(verdictResponse);
    }

    public async Task<VaasVerdict> ForSha256Async(ChecksumSha256 sha256, CancellationToken cancellationToken, ForSha256Options? options = null)
    {
        var url = _options.Url;
        var authority = _options.Url.Authority.Replace("gateway", "upload");
        var scheme = url.Scheme == "wss" ? "https" : "http";
        //TODO: Replace hash in url path with sha256
        url = new Uri($"{scheme}://{authority}/verdicts/hash/{sha256}");
        
        var response = await _httpClient.GetAsync(url, cancellationToken);
        //TODO: Error handling 
        //TODO: Timeout
        var verdictResponse = JsonSerializer.Deserialize<VerdictResponse>(await response.Content.ReadAsStringAsync(cancellationToken)) ?? throw new InvalidOperationException();
        return new VaasVerdict(verdictResponse);
    }

    public async Task<VaasVerdict> ForFileAsync(string path, CancellationToken cancellationToken, Dictionary<string, string>? verdictRequestAttributes = null)
    {
        var sha256 = Sha256CheckSum(path);
        var verdictResponse = await ForRequestAsync(
            new VerdictRequest(sha256, SessionId ?? throw new InvalidOperationException())
            {
                UseCache = _options.UseCache,
                UseShed = _options.UseHashLookup,
                VerdictRequestAttributes = verdictRequestAttributes
            });
        if (!verdictResponse.IsValid)
            throw new JsonException("VerdictResponse is not valid");
        if (verdictResponse.Verdict != Verdict.Unknown)
            return new VaasVerdict(verdictResponse);
        if (string.IsNullOrWhiteSpace(verdictResponse.Url) ||
            string.IsNullOrWhiteSpace(verdictResponse.UploadToken))
        {
            throw new JsonException("VerdictResponse is not valid");
        }

        var response = WaitForResponseAsync(verdictResponse.Guid);
        await UploadFile(path, verdictResponse.Url, verdictResponse.UploadToken);

        return new VaasVerdict(await response);
    }

    private async Task UploadFile(string path, string url, string token)
    {
        await using var fileStream = File.OpenRead(path);
        using var streamContent = new StreamContent(fileStream);
        using var request = new HttpRequestMessage(HttpMethod.Put, url);

        request.Headers.Authorization = new AuthenticationHeaderValue(token);
        request.Content = streamContent;
        var httpResponse = await _httpClient.SendAsync(request);

        if (!httpResponse.IsSuccessStatusCode)
        {
            var body = await httpResponse.Content.ReadAsStringAsync();
            try
            {
                var problemDetails = JsonSerializer.Deserialize<ProblemDetails>(body);
                throw ProblemDetailsToException(problemDetails);
            }
            catch (Exception)
            {
                throw new VaasServerException("Server did not return ProblemDetails");
            }
        }
    }

    public async Task<List<VaasVerdict>> ForSha256ListAsync(IEnumerable<string> sha256List, CancellationToken cancellationToken)
    {
        return (await Task.WhenAll(sha256List.Select(async sha256 => await ForSha256Async(new ChecksumSha256(sha256), cancellationToken)))).ToList();
    }

    public async Task<List<VaasVerdict>> ForFileListAsync(IEnumerable<string> fileList, CancellationToken cancellationToken)
    {
        return (await Task.WhenAll(fileList.Select(async filePath => await ForFileAsync(filePath, cancellationToken)))).ToList();
    }

    private async Task<VerdictResponse> ForRequestAsync(VerdictRequest verdictRequest)
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

        AuthenticatedClient.Dispose();
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