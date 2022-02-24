using System;
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
            DotNetEnv.Env.TraversePath().Load();
            var myToken =DotNetEnv.Env.GetString("VAAS_TOKEN");
            var vaas = new Vaas(myToken);
            if (vaas.Authenticate() == false)
            {
                throw new UnauthorizedAccessException();
            }
            var verdict = vaas.ForSha256("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
            Assert.Equal(Verdict.Malicious, verdict);
            
        }
    }
}
