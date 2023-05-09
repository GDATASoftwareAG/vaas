using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Vaas.Messages;
using Websocket.Client;
using Websocket.Client.Exceptions;

namespace Vaas;

public class Vaas : IDisposable
{
    private const int AuthenticationTimeoutInMs = 1000;

    private WebsocketClient? _client;
    private WebsocketClient AuthenticatedClient => GetAuthenticatedWebSocket();

    private readonly HttpClient _httpClient = new();

    private string? SessionId { get; set; }
    private bool AuthenticatedErrorOccured { get; set; }

    private readonly TaskCompletionSource _authenticatedSource = new();
    private Task Authenticated => _authenticatedSource.Task;

    public Uri Url { get; set; } = new("wss://gateway.production.vaas.gdatasecurity.de");

    private readonly ConcurrentDictionary<string, TaskCompletionSource<VerdictResponse>> _verdictResponses = new();

    private readonly VaasOptions _options;

    public Vaas(VaasOptions? options = null)
    {
        _options = options ?? VaasOptions.Defaults;
    }

    public async Task Connect(string token)
    {
        _client = new WebsocketClient(Url, WebsocketClientFactory);
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
                if (!_verdictResponses.TryRemove(verdictResponse.Guid, out var tcs))
                {
                    // Error: Server sent guid we are not waiting for, ignore it
                    return;
                }
                tcs.SetResult(verdictResponse);
                break;
        }
    }

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

    public async Task<VaasVerdict> ForUrlAsync(Uri uri)
    {
        var verdictResponse = await ForUrlRequestAsync(new VerdictRequestForUrl(uri, SessionId ?? throw new VaasInvalidStateException())
        {
            UseCache = _options.UseCache,
            UseShed = _options.UseShed
        });
        return new VaasVerdict(verdictResponse);
    }

    public async Task<VaasVerdict> ForSha256Async(string sha256)
    {
        var verdictResponse = await ForRequestAsync(new VerdictRequest(sha256, SessionId ?? throw new VaasInvalidStateException())
        {
            UseCache = _options.UseCache,
            UseShed = _options.UseShed
        });
        return new VaasVerdict(verdictResponse);
    }

    public async Task<VaasVerdict> ForFileAsync(string path)
    {
        var sha256 = Sha256CheckSum(path);
        var verdictResponse = await ForRequestAsync(
            new VerdictRequest(sha256, SessionId ?? throw new InvalidOperationException())
            {
                UseCache = _options.UseCache,
                UseShed = _options.UseShed
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

        httpResponse.EnsureSuccessStatusCode();
    }

    public async Task<List<VaasVerdict>> ForSha256ListAsync(IEnumerable<string> sha256List)
    {
        return (await Task.WhenAll(sha256List.Select(ForSha256Async))).ToList();
    }

    public async Task<List<VaasVerdict>> ForFileListAsync(IEnumerable<string> fileList)
    {
        return (await Task.WhenAll(fileList.Select(ForFileAsync))).ToList();
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

        AuthenticatedClient?.Dispose();
        _httpClient.Dispose();
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    public WebsocketClient GetAuthenticatedWebSocket()
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