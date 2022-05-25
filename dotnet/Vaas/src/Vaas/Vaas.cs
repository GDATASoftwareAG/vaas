using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Vaas.Messages;
using Websocket.Client;
using Websocket.Client.Exceptions;

namespace Vaas
{
    public class Vaas : IDisposable
    {
        private const int AuthenticationTimeoutInMs = 1000;
        
        private string Token { get; }

        private WebsocketClient? Client { get; set; }
        private readonly HttpClient _httpClient = new();
        
        private string? SessionId { get; set; }

        private readonly TaskCompletionSource _authenticatedSource = new();
        private Task Authenticated => _authenticatedSource.Task;
        
        public Uri Url { get; init; } = new("wss://gateway-vaas.gdatasecurity.de");

        private Dictionary<string, VerdictResponse> VerdictResponsesDict { get; } = new();

        public Vaas(string token)
        {
            Token = token;
        }

        public async Task Connect()
        {
            Client = new WebsocketClient(Url, WebsocketClientFactory);
            Client.ReconnectTimeout = null;
            Client.MessageReceived.Subscribe(HandleResponseMessage);
            await Client.Start();
            if (!Client.IsStarted)
            {
                throw new WebsocketException("Could not start client");
            }
            
            await Authenticate();
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
                    VerdictResponsesDict.Add(verdictResponse?.Guid ?? throw new InvalidOperationException(), verdictResponse);
                    break;
            }
        }

        private async Task Authenticate()
        {
            var authenticationRequest = new AuthenticationRequest(Token);
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
            if (verdictResponse.Verdict != Verdict.Unknown) return verdictResponse.Verdict;
            var url = verdictResponse.Url;
            if (url is null) throw new ArgumentNullException(nameof(url));
            
            var token = verdictResponse.UploadToken ?? "";

            await UploadFile(path, url, token);
            
            var response = await WaitForResponseAsync(verdictResponse.Guid);

            return response.Verdict;
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
            await Task.Run(()=>Client?.Send(jsonString));

            return await WaitForResponseAsync(analysisRequest.Guid);
        }
        
        private async Task<VerdictResponse> WaitForResponseAsync(string guid)
        {
            VerdictResponse? value;
            while (VerdictResponsesDict.TryGetValue(guid, out value) == false)
            {
                await Task.Delay(300);
            }
            VerdictResponsesDict.Remove(guid);
            return value;
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
            if (disposing)
            {
                Client?.Dispose();
                _httpClient.Dispose();
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}