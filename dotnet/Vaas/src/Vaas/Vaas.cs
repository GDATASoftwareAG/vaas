using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
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
        private string Token { get; }

        private WebsocketClient? Client { get; set; }

        private string? SessionId { get; set; }

        private bool Authenticated { get; set; }
        
        public Uri Url { get; set; } = new("wss://gateway-vaas.gdatasecurity.de");

        private Dictionary<string, VerdictResponse> VerdictResponsesDict { get; } = new();

        public Vaas(string token)
        {
            Token = token;
        }

        public async Task Connect()
        {
            Client = new WebsocketClient(Url, CreateWebsocketClient());
            Client.ReconnectTimeout = null;
            Client.MessageReceived.Subscribe(HandleResponseMessage);
            await Client.Start();
            if (!Client.IsStarted)
            {
                throw new WebsocketException("Could not start client");
            }
            
            Authenticate();
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
                        Authenticated = true;
                        SessionId = authenticationResponse.SessionId;
                    }

                    break;

                case "VerdictResponse":
                    var options = new JsonSerializerOptions { Converters = { new JsonStringEnumConverter() } };
                    var verdictResponse = JsonSerializer.Deserialize<VerdictResponse>(msg.Text, options);
                    VerdictResponsesDict.Add(verdictResponse?.Guid ?? throw new InvalidOperationException(), verdictResponse);
                    break;
            }
        }

        private void Authenticate()
        {
            var authenticationRequest = new AuthenticationRequest(Token);
            var jsonString = JsonSerializer.Serialize(authenticationRequest);
            Client?.Send(jsonString);
            for (var i = 0; i < 10; i++)
            {
                if (Authenticated)
                {
                    break;
                }

                Thread.Sleep(100);
            }

            if (Authenticated != true)
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
            
            var token = verdictResponse.UploadToken;
            var data = await File.ReadAllBytesAsync(path);
            using (var client = new WebClient())
            {
                client.Headers.Add(HttpRequestHeader.Authorization, token);
                client.UploadData(url, "PUT", data);
            }
            var response = await WaitForResponseAsync(verdictResponse.Guid);

            return response.Verdict;
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

        private static Func<ClientWebSocket> CreateWebsocketClient()
        {
            return () =>
            {
                var clientWebSocket = new ClientWebSocket
                {
                    Options =
                    {
                        KeepAliveInterval = TimeSpan.FromSeconds(20)
                    }
                };
                return clientWebSocket;
            };
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                Client?.Dispose();
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}