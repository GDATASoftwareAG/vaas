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
    
    private WebsocketClient? Client { get; set; }
    private readonly HttpClient _httpClient = new();
        
    private string? SessionId { get; set; }

    private readonly TaskCompletionSource _authenticatedSource = new();
    private Task Authenticated => _authenticatedSource.Task;

    private Uri _url = new("wss://gateway-vaas.gdatasecurity.de");

    private readonly ConcurrentDictionary<string, TaskCompletionSource<VerdictResponse>> _verdictResponses = new();
    

    public async Task Connect(string token)
    {
        Client = new WebsocketClient(_url, WebsocketClientFactory);
        Client.ReconnectTimeout = null;
        Client.MessageReceived.Subscribe(HandleResponseMessage);
        await Client.Start();
        if (!Client.IsStarted)
        {
            throw new WebsocketException("Could not start client");
        }
            
        await Authenticate(token);
    }

    public async Task ConnectWithCredentials(string clientId, string clientSecret, Uri tokenEndpoint, string url = "wss://gateway-vaas.gdatasecurity.de")
    {
        var response = await _httpClient.PostAsync(tokenEndpoint, new FormUrlEncodedContent(
            new List<KeyValuePair<string, string>>
            {
                new("client_id", clientId),
                new("client_secret", clientSecret),
                new("grant_type", "client_credentials")
            }));
        var stringResponse = await response.Content.ReadAsStringAsync();
        var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(stringResponse);
        if (tokenResponse == null)
            throw new JsonException("Access token is null");
        
        _url = new Uri(url);
        await Connect(tokenResponse.AccessToken);
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
                    SessionId = authenticationResponse.SessionId;
                    _authenticatedSource.SetResult();
                }

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
        Client?.Send(jsonString);

        var delay = Task.Delay(AuthenticationTimeoutInMs);
        if (await Task.WhenAny(Authenticated, delay) == delay)
        {
            throw new UnauthorizedAccessException();
        }
    }

    public async Task<Verdict> ForSha256Async(string sha256)
    {
        var value = await ForRequestAsync(new AnalysisRequest(sha256,SessionId ?? throw new InvalidOperationException()));
        return value.Verdict;
    }
        
    public async Task<Verdict> ForFileAsync(string path)
    {
        var sha256 = Sha256CheckSum(path);
        var verdictResponse = await ForRequestAsync(new AnalysisRequest(sha256, SessionId ?? throw new InvalidOperationException()));
        if (!verdictResponse.IsValid)
            throw new JsonException("VerdictResponse is not valid");
        if (verdictResponse.Verdict != Verdict.Unknown) return verdictResponse.Verdict;
        if (string.IsNullOrWhiteSpace(verdictResponse.Url) ||
            string.IsNullOrWhiteSpace(verdictResponse.UploadToken))
        {
            throw new JsonException("VerdictResponse is not valid");
        }

        var response = WaitForResponseAsync(verdictResponse.Guid);

        await UploadFile(path, verdictResponse.Url, verdictResponse.UploadToken);
        
        return (await response).Verdict;
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

    public async Task<List<Verdict>> ForSha256ListAsync(IEnumerable<string> sha256List)
    {
        return (await Task.WhenAll(sha256List.Select(ForSha256Async))).ToList();
    }

    public async Task<List<Verdict>> ForFileListAsync(IEnumerable<string> fileList)
    {
        return (await Task.WhenAll(fileList.Select(ForFileAsync))).ToList();
    }

        
    private async Task<VerdictResponse> ForRequestAsync(AnalysisRequest analysisRequest)
    {
        var jsonString = JsonSerializer.Serialize(analysisRequest);
        Client?.Send(jsonString);

        return await WaitForResponseAsync(analysisRequest.Guid);
    }
        
    private Task<VerdictResponse> WaitForResponseAsync(string guid)
    {
        var tcs = _verdictResponses.GetOrAdd(guid, _ => new TaskCompletionSource<VerdictResponse>());
        return tcs.Task;
    }
        
    private static string Sha256CheckSum(string filePath)
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
        
        Client?.Dispose();
        _httpClient.Dispose();
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}