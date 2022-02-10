using System;
using System.Threading.Tasks;
using Websocket.Client;

namespace Vaas
{
    public class Vaas
    {
        public Verdict ForSha256(string sha256)
        {
            var url = new Uri("wss://gateway-vaas.gdatasecurity.de");

            using (var client = new WebsocketClient(url))
            {
                client.ReconnectTimeout = null;
                client.MessageReceived.Subscribe(msg => Console.WriteLine($"Message received: {msg}"));
                client.Start();

                client.Send("{ message }");
            }
            return Verdict.Clean;
        } 
    }
}
