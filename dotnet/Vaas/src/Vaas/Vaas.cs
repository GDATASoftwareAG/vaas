using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
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
    public class Vaas
    {
        private string Token { get; }

        public WebsocketClient Client { get; set; }

        public string SessionId { get; set; }

        public bool Authenticated { get; set; }
        
        public Uri Url { get; set; } = new Uri("wss://gateway-vaas.gdatasecurity.de");

        private Dictionary<string, VerdictResponse> VerdictResponsesDict { get; } = new Dictionary<string, VerdictResponse>();

        public Vaas(string token)
        {
            Token = token;
        }

        public void Connect()
        {
            Client = new WebsocketClient(Url, CreateWebsocketClient()); //WEBSOCKET OFFEN LASSEN - PING SENDEN
            Client.ReconnectTimeout = null;
            Client.MessageReceived.Subscribe(msg =>
            {
                if (msg.MessageType == WebSocketMessageType.Text)
                {
                    var message = JsonSerializer.Deserialize<Message>(msg.Text);
                    switch (message.Kind)
                    {
                        case "AuthResponse":
                            var authenticationResponse = JsonSerializer.Deserialize<AuthenticationResponse>(msg.Text);
                            if (authenticationResponse.Success == true)
                            {
                                Authenticated = true;
                                SessionId = authenticationResponse.SessionId;
                            }
                            break;
                        
                        case "VerdictResponse":
                            var options = new JsonSerializerOptions() {Converters = {new JsonStringEnumConverter()}};
                            var verdictResponse = JsonSerializer.Deserialize<VerdictResponse>(msg.Text,options);
                            VerdictResponsesDict.Add(verdictResponse.Guid, verdictResponse);
                            break;
                    }
                   
                }
            });
            Client.Start().GetAwaiter().GetResult();
            if (!Client.IsStarted)
            {
                throw new WebsocketException("Could not start client");
            }

            Authenticate();
        }

        private void Authenticate()
        {
            var authenticationRequest = new AuthenticationRequest(Token, null);
            string jsonString = JsonSerializer.Serialize(authenticationRequest);
            Client.Send(jsonString);
            for (var i = 0; i < 10; i++)
            {
                if (Authenticated == true)
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

        public Verdict ForSha256(string sha256)
        {
            var value = ForRequest(new AnalysisRequest(sha256,SessionId));
            return value.Verdict;
        }
        
        public Verdict ForFile(string path)
        {
            var sha256 = SHA256CheckSum(path);
            var verdictResponse = ForRequest(new AnalysisRequest(sha256, SessionId));
            if (verdictResponse.Verdict == Verdict.Unknown)
            {
                var url = verdictResponse.Url;
                var token = verdictResponse.UploadToken;

                var httpRequest = (HttpWebRequest) WebRequest.Create(url);
                httpRequest.Method = "PUT";
                httpRequest.Headers.Add(HttpRequestHeader.Authorization, token);

                var data = File.ReadAllBytes(path);
                using (var streamWriter = new StreamWriter(httpRequest.GetRequestStream()))
                {
                    streamWriter.Write(data);
                }

                var httpResponse = (HttpWebResponse) httpRequest.GetResponse();
                if (httpResponse.StatusCode != HttpStatusCode.OK)
                {
                    throw new HttpRequestException("file upload failed");
                }

                VerdictResponse value;
                while (VerdictResponsesDict.TryGetValue(verdictResponse.Guid, out value) == false)
                {
                    Thread.Sleep(300);
                }

                VerdictResponsesDict.Remove(verdictResponse.Guid);

                return value.Verdict;

            }

            return verdictResponse.Verdict;
        }

        private VerdictResponse ForRequest(AnalysisRequest analysisRequest)
        {
            var jsonString = JsonSerializer.Serialize(analysisRequest);
            Client.Send(jsonString);
            VerdictResponse value;
            while (VerdictResponsesDict.TryGetValue(analysisRequest.Guid, out value) == false)
            {
                Thread.Sleep(300);
            }
            VerdictResponsesDict.Remove(analysisRequest.Guid);

            return value;
        }
        
        public string SHA256CheckSum(string filePath)
        {
            using (SHA256 SHA256 = SHA256Managed.Create())
            {
                using (FileStream fileStream = File.OpenRead(filePath))
                    return Convert.ToHexString(SHA256.ComputeHash(fileStream));
            }
        }

        private static Func<ClientWebSocket> CreateWebsocketClient()
        {
            return () =>
            {
                var clientWebSocket = new ClientWebSocket
                {
                    Options =
                    {
                        KeepAliveInterval = TimeSpan.FromSeconds(30)
                    }
                };
                return clientWebSocket;
            };
        }
    }
}