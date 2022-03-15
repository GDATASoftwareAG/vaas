using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace Vaas.Test
{
    public class IntegrationTests
    {
        // public class RealApiIntegrationTests {
        //     @Test
        //     public void fromSha256SingleMaliciousHash() throws Exception {
        //         var vaas = this.getVaas();
        //     var sha256 = new Sha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
        //     var cts = new CancellationTokenSource(Duration.ofSeconds(10));
        //
        //     var verdict = vaas.forSha256(sha256, cts);
        //     vaas.disconnect();
        //
        //     assertEquals(Verdict.MALICIOUS, verdict.getVerdict());
        // }
        [Fact]
        public void FromSha256SingleMaliciousHash()
        {
            var vaas = Authenticate();
            var verdict = vaas.ForSha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
            Assert.Equal(Verdict.Malicious, verdict);
        }
        
        [Fact]
        public void FromSha256SingleCleanHash()
        {
            var vaas = Authenticate();
            var verdict = vaas.ForSha256("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23");
            Assert.Equal(Verdict.Clean, verdict);
        }
        
        [Fact]
        public void FromSha256SingleUnknownHash()
        {
            var vaas = Authenticate();
            var verdict = vaas.ForSha256("110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe9");
            Assert.Equal(Verdict.Unknown, verdict);
        }

        [Fact]
        public async Task GenerateFileUnknownHash()
        {
            Random rnd = new Random();
            Byte[] b = new Byte[50];
            rnd.NextBytes(b);
            await File.WriteAllBytesAsync("test.txt", b);
            var vaas = Authenticate();
            vaas.ForFile("test.txt");
        }

        private Vaas Authenticate()
        {
            DotNetEnv.Env.TraversePath().Load();
            var myToken = DotNetEnv.Env.GetString("VAAS_TOKEN");
            var vaas = new Vaas(myToken);
            vaas.Connect();
            return vaas;
        }
    }
}