using System;
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

        public WebsocketClient Client { get; }
        
        public bool Authenticated { get; set; }

        public Vaas(string token)
        {
            Token = token;

            var url = new Uri("wss://gateway-vaas.gdatasecurity.de");

            Client = new WebsocketClient(url, CreateWebsocketClient());
            Client.ReconnectTimeout = null;
            Client.MessageReceived.Subscribe(msg =>
            {
                if (msg.MessageType == WebSocketMessageType.Text)
                {
                    var response = JsonSerializer.Deserialize<AuthenticationResponse>(msg.Text);
                    if (response.Success == true)
                    {
                        Authenticated = true;
                    }
                }
            });
            Client.Start().GetAwaiter().GetResult();
            if (!Client.IsStarted)
            {
                throw new WebsocketException("Could not start client");
            }

            
        }

        public bool Authenticate()
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
            return Authenticated;
        }

        public Verdict ForSha256(string sha256)
        {
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