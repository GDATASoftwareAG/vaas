using System;
using System.Collections.Generic;
using System.Net.WebSockets;
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

        private Dictionary<string, Verdict> VerdictDict { get; } = new Dictionary<string, Verdict>();

        public Vaas(string token)
        {
            Token = token;
        }

        public void Connect()
        {
            Client = new WebsocketClient(Url, CreateWebsocketClient());
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
                            VerdictDict.Add(verdictResponse.Guid, verdictResponse.Verdict);
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
            var analysisRequest = new AnalysisRequest(sha256, SessionId);
            string jsonString = JsonSerializer.Serialize(analysisRequest);
            Client.Send(jsonString);
            Verdict value;
            while (VerdictDict.TryGetValue(analysisRequest.Guid, out value) == false)
            {
                Thread.Sleep(300);
            }
            VerdictDict.Remove(analysisRequest.Guid);
            return value;
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