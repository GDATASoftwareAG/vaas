using System;
using System.Net.WebSockets;
using System.Text.Json;
using System.Threading.Tasks;
using Vaas.Messages;
using Websocket.Client;
using Websocket.Client.Exceptions;

namespace Vaas
{
    public class Vaas
    {
        public Verdict ForSha256(string sha256)
        {
            var url = new Uri("wss://gateway-vaas.gdatasecurity.de");

            using (var client = new WebsocketClient(url, CreateWebsocketClient()))
            {
                client.ReconnectTimeout = null;
                client.MessageReceived.Subscribe(msg => Console.WriteLine($"Message received: {msg}"));
                client.Start().GetAwaiter().GetResult();
                if (!client.IsStarted)
                {
                    throw new WebsocketException("Could not start client");
                }

                var authenticationRequest = new AuthenticationRequest("1023456789", null);

                string jsonString = JsonSerializer.Serialize(authenticationRequest);
                
                client.Send(jsonString);
            }
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
