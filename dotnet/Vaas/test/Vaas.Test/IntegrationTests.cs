using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace Vaas.Test;

public class IntegrationTests
{
    [Fact]
    public async void FromSha256SingleMaliciousHash()
    {
        var vaas = await AuthenticateWithCredentials();
        var verdict = await vaas.ForSha256Async("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");
        Assert.Equal(Verdict.Malicious, verdict);
    }

    [Fact]
    public async void FromSha256SingleCleanHash()
    {
        var vaas = await AuthenticateWithCredentials();
        var verdict = await vaas.ForSha256Async("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23");
        Assert.Equal(Verdict.Clean, verdict);
    }

    [Fact(Skip = "Remove Skip to test keepalive")]
    public async void FromSha256_WorksAfter40s()
    {
        var vaas = await AuthenticateWithCredentials();
        const string guid = "698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23";
        var verdict = await vaas.ForSha256Async(guid);
        Assert.Equal(Verdict.Clean, verdict);
        await Task.Delay(40000);
        verdict = await vaas.ForSha256Async(guid);
        Assert.Equal(Verdict.Clean, verdict);
    }

    [Fact]
    public async void FromSha256SingleUnknownHash()
    {
        var vaas = await AuthenticateWithCredentials();
        var verdict = await vaas.ForSha256Async("110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe9");
        Assert.Equal(Verdict.Unknown, verdict);
    }

    [Fact]
    public async void From256ListMultipleHashes()
    {
        var myList = new List<string>
        {
            "000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8",
            "698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23",
            "110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe9"
        };
        var vaas = await AuthenticateWithCredentials();
        var verdictList = await vaas.ForSha256ListAsync(myList);
        Assert.Equal(Verdict.Malicious, verdictList[0]);
        Assert.Equal(Verdict.Clean, verdictList[1]);
        Assert.Equal(Verdict.Unknown, verdictList[2]);
    }


    [Fact]
    public async Task GenerateFileUnknownHash()
    {
        var rnd = new Random();
        var b = new byte[50];
        rnd.NextBytes(b);
        await File.WriteAllBytesAsync("test.txt", b);
        var vaas = await AuthenticateWithCredentials();
        var result = await vaas.ForFileAsync("test.txt");
        Assert.Equal(Verdict.Clean, result);
    }

    [Fact]
    public async Task GenerateFileList()
    {
        var rnd = new Random();
        var b = new byte[50];
        rnd.NextBytes(b);
        await File.WriteAllBytesAsync("test1.txt", b);
        rnd.NextBytes(b);
        await File.WriteAllBytesAsync("test2.txt", b);
        rnd.NextBytes(b);
        await File.WriteAllBytesAsync("test3.txt", b);
        var vaas = await AuthenticateWithCredentials();
        var resultList = await vaas.ForFileListAsync(new List<string> {"test1.txt", "test2.txt", "test3.txt"});
        Assert.Equal(Verdict.Clean, resultList[0]);
        Assert.Equal(Verdict.Clean, resultList[1]);
        Assert.Equal(Verdict.Clean, resultList[2]);
    }


    [Fact]
    public async void FromSha256_ReturnsPup_ForAmtsoSample()
    {
        var vaas = await AuthenticateWithCredentials();
        var actual = await vaas.ForSha256Async("d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad");
        Assert.Equal(Verdict.Pup, actual);
    }

    private static async Task<Vaas> AuthenticateWithCredentials()
    {
        DotNetEnv.Env.TraversePath().Load();
        var url = DotNetEnv.Env.GetString(
            "VAAS_URL",
            "wss://gateway-vaas.gdatasecurity.de");
        var tokenEndpoint = new Uri(DotNetEnv.Env.GetString(
            "TOKEN_URL",
            "https://keycloak-vaas.gdatasecurity.de/realms/vaas/protocol/openid-connect/token"));
        var clientId = DotNetEnv.Env.GetString("CLIENT_ID");
        var clientSecret = DotNetEnv.Env.GetString("CLIENT_SECRET");
        var vaas = new Vaas();
        await vaas.ConnectWithCredentials(clientId, clientSecret, tokenEndpoint, url);
        return vaas;
    }

    [Fact]
    public async Task UploadEmptyFile()
    {
        await File.WriteAllBytesAsync("empty.txt", Array.Empty<byte>());
        var vaas = await AuthenticateWithCredentials();
        var result = await vaas.ForFileAsync("empty.txt");
        Assert.Equal(Verdict.Clean, result);
    }
}