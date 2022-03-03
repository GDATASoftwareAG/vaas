﻿using System;
using System.Net.WebSockets;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Vaas.Messages;
using Websocket.Client;
using Websocket.Client.Exceptions;

namespace Vaas
{
    public class Vaas
    {
        public string Token { get; }

        public WebsocketClient Client { get; set; }

        public string SessionId { get; set; }

        public bool Authenticated { get; set; }

        public Uri Url { get; set; } = new Uri("wss://gateway-vaas.gdatasecurity.de");

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
                    var response = JsonSerializer.Deserialize<AuthenticationResponse>(msg.Text);
                    if (response.Success == true)
                    {
                        Authenticated = true;
                        SessionId = response.SessionId;
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

            return Verdict.Clean;
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