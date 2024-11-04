using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Memory;
using Microsoft.Extensions.DependencyInjection;
using Vaas.Test.Authentication;
using Xunit;
using Xunit.Abstractions;

namespace Vaas.Test;

public class IntegrationTests
{
    private static Uri VaasUrl => new Uri(DotNetEnv.Env.GetString(
        "VAAS_URL",
        "wss://gateway.production.vaas.gdatasecurity.de"));

    private readonly ITestOutputHelper _output;
    private readonly HttpClient _httpClient = new();

    public IntegrationTests(ITestOutputHelper output)
    {
        _output = output;
        DotNetEnv.Env.TraversePath().Load();
    }

    [Fact]
    public async Task ConnectWithWrongCredentialsThrowsVaasAuthenticationException()
    {
        var services = GetServices(new Dictionary<string, string>()
        {
            { "VerdictAsAService:Url", VaasUrl.ToString() },
            { "VerdictAsAService:TokenUrl", AuthenticationEnvironment.TokenUrl.ToString() },
            { "VerdictAsAService:Credentials:GrantType", "ClientCredentials" },
            { "VerdictAsAService:Credentials:ClientId", "foobar" },
            { "VerdictAsAService:Credentials:ClientSecret", "foobar2" },
        });
        var provider = services.BuildServiceProvider();

        var vaas = provider.GetRequiredService<IVaas>();
        await Assert.ThrowsAsync<VaasAuthenticationException>(async () =>
            await vaas.Connect(CancellationToken.None));
    }

    [Fact]
    public async Task FromSha256SingleMaliciousHash()
    {
        var vaas = await AuthenticateWithCredentials();
        var verdict = await vaas.ForSha256Async(
            new ChecksumSha256("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2"),
            CancellationToken.None);
        Assert.Equal(Verdict.Malicious, verdict.Verdict);
        Assert.Equal("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2", verdict.Sha256);
    }

    [Fact]
    public async Task FromSha256SingleCleanHash()
    {
        var vaas = await AuthenticateWithCredentials();
        var verdict = await vaas.ForSha256Async(
            new ChecksumSha256("cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e"),
            CancellationToken.None);
        Assert.Equal(Verdict.Clean, verdict.Verdict);
        Assert.Equal("cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e", verdict.Sha256, true);
    }

    [Fact(Skip = "Remove Skip to test keepalive")]
    public async Task FromSha256_WorksAfter40s()
    {
        var vaas = await AuthenticateWithCredentials();
        const string guid = "3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C";
        var verdict = await vaas.ForSha256Async(new ChecksumSha256(guid), CancellationToken.None);
        Assert.Equal(Verdict.Clean, verdict.Verdict);
        Assert.Equal("3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C", verdict.Sha256, true);
        await Task.Delay(40000);
        verdict = await vaas.ForSha256Async(new ChecksumSha256(guid), CancellationToken.None);
        Assert.Equal(Verdict.Clean, verdict.Verdict);
        Assert.Equal("3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C", verdict.Sha256, true);
    }

    [Fact]
    public async Task FromSha256SingleUnknownHash()
    {
        var vaas = await AuthenticateWithCredentials();
        var verdict = await vaas.ForSha256Async(
            new ChecksumSha256("110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe9"),
            CancellationToken.None);
        Assert.Equal(Verdict.Unknown, verdict.Verdict);
        Assert.Equal("110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe9", verdict.Sha256);
    }

    [Fact]
    public async Task From256ListMultipleHashes()
    {
        var myList = new List<string>
        {
            "ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2",
            "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e",
            "1f72c1111111111111f912e40b7323a0192a300b376186c10f6803dc5efe28df"
        };
        var vaas = await AuthenticateWithCredentials();
        var verdictList = await vaas.ForSha256ListAsync(myList, CancellationToken.None);
        Assert.Equal(Verdict.Malicious, verdictList[0].Verdict);
        Assert.Equal("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2", verdictList[0].Sha256, true);
        Assert.Equal(Verdict.Clean, verdictList[1].Verdict);
        Assert.Equal("cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e", verdictList[1].Sha256, true);
        Assert.Equal(Verdict.Unknown, verdictList[2].Verdict);
        Assert.Equal("1f72c1111111111111f912e40b7323a0192a300b376186c10f6803dc5efe28df", verdictList[2].Sha256, true);
    }


    [Fact]
    public async Task GenerateFileUnknownHash()
    {
        var rnd = new Random();
        var b = new byte[50];
        rnd.NextBytes(b);
        await File.WriteAllBytesAsync("test.txt", b);
        var vaas = await AuthenticateWithCredentials();
        var result = await vaas.ForFileAsync("test.txt", CancellationToken.None);
        Assert.Equal(Verdict.Clean, result.Verdict);
        Assert.Equal(Vaas.Sha256CheckSum("test.txt"), result.Sha256);
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
        var resultList = await vaas.ForFileListAsync(new List<string> { "test1.txt", "test2.txt", "test3.txt" },
            CancellationToken.None);
        Assert.Equal(Verdict.Clean, resultList[0].Verdict);
        Assert.Equal(Vaas.Sha256CheckSum("test1.txt"), resultList[0].Sha256);
        Assert.Equal(Verdict.Clean, resultList[1].Verdict);
        Assert.Equal(Vaas.Sha256CheckSum("test2.txt"), resultList[1].Sha256);
        Assert.Equal(Verdict.Clean, resultList[2].Verdict);
        Assert.Equal(Vaas.Sha256CheckSum("test3.txt"), resultList[2].Sha256);
    }

    // [Fact]
    // public async Task FromSha256_ReturnsPup_ForAmtsoSample()
    // {
    //     var vaas = await AuthenticateWithCredentials();
    //     var actual = await vaas.ForSha256Async(
    //         new ChecksumSha256("d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad"),
    //         CancellationToken.None);
    //     Assert.Equal(Verdict.Pup, actual.Verdict);
    //     Assert.Equal("d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad", actual.Sha256, true);
    // }

    [Theory]
    [InlineData("https://www.gdatasoftware.com/oem/verdict-as-a-service", Verdict.Clean)]
    [InlineData("https://secure.eicar.org/eicar.com", Verdict.Malicious)]
    public async Task FromUrlReturnVerdict(string url, Verdict verdict)
    {
        var vaas = await AuthenticateWithCredentials();
        var actual = await vaas.ForUrlAsync(new Uri(url), CancellationToken.None);
        Assert.Equal(verdict, actual.Verdict);
    }

    [Fact]
    public async Task ForUrl_WithUrlWithStatusCode4xx_ThrowsVaasClientException()
    {
        var vaas = await AuthenticateWithCredentials();
        var e = await Assert.ThrowsAsync<VaasClientException>(() =>
            vaas.ForUrlAsync(new Uri("https://gateway.production.vaas.gdatasecurity.de/swagger/nocontenthere"),
                CancellationToken.None));
        Assert.Equal(
            "Call failed with status code 404 (Not Found): GET https://gateway.production.vaas.gdatasecurity.de/swagger/nocontenthere",
            e.Message);
    }

    [Fact]
    public async Task ForStream_WithEicarString_ReturnsMalicious()
    {
        // Arrange
        var vaas = await AuthenticateWithCredentials();
        var targetStream = new MemoryStream();
        var eicarBytes = System.Text.Encoding.UTF8.GetBytes("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
        targetStream.Write(eicarBytes, 0, eicarBytes.Length);
        targetStream.Position = 0;

        // Act
        var verdict = await vaas.ForStreamAsync(targetStream, CancellationToken.None);

        // Assert
        Assert.Equal(Verdict.Malicious, verdict.Verdict);
    }

    [Fact]
    public async Task ForStream_WithCleanString_ReturnsClean()
    {
        // Arrange
        var vaas = await AuthenticateWithCredentials();
        var targetStream = new MemoryStream();
        var cleanBytes = System.Text.Encoding.UTF8.GetBytes("This is a clean file");
        targetStream.Write(cleanBytes, 0, cleanBytes.Length);
        targetStream.Position = 0;

        // Act
        var verdict = await vaas.ForStreamAsync(targetStream, CancellationToken.None);

        // Assert
        Assert.Equal(Verdict.Clean, verdict.Verdict);
    }

    [Fact]
    public async Task ForStream_WithCleanUrl_ReturnsClean()
    {
        // Arrange
        var vaas = await AuthenticateWithCredentials();
        var url = new Uri("https://raw.githubusercontent.com/GDATASoftwareAG/vaas/main/Readme.md");
        var response = await _httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Get, url), CancellationToken.None);
        var targetStream = await response.Content.ReadAsStreamAsync();

        // Act
        var verdict = await vaas.ForStreamAsync(targetStream, CancellationToken.None);

        // Assert
        Assert.Equal(Verdict.Clean, verdict.Verdict);
    }

    [Fact]
    public async Task ForStream_WithEicarUrl_ReturnsEicar()
    {
        // Arrange
        var vaas = await AuthenticateWithCredentials();
        var url = new Uri("https://secure.eicar.org/eicar.com.txt");
        var response = await _httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Get, url), CancellationToken.None);
        var targetStream = await response.Content.ReadAsStreamAsync();

        // Act
        var verdict = await vaas.ForStreamAsync(targetStream, CancellationToken.None);

        // Assert
        Assert.Equal(Verdict.Malicious, verdict.Verdict);
    }

    private async Task<Vaas> AuthenticateWithCredentials()
    {
        var services = GetServices(new Dictionary<string, string>()
        {
            { "VerdictAsAService:Url", VaasUrl.ToString() },
            { "VerdictAsAService:TokenUrl", AuthenticationEnvironment.TokenUrl.ToString() },
            { "VerdictAsAService:Credentials:GrantType", "ClientCredentials" },
            { "VerdictAsAService:Credentials:ClientId", AuthenticationEnvironment.ClientId },
            { "VerdictAsAService:Credentials:ClientSecret", AuthenticationEnvironment.ClientSecret },
            { "VerdictAsAService:UseCache", "false" }
        });
        ServiceCollectionTools.Output(_output, services);
        var provider = services.BuildServiceProvider();

        var vaas = provider.GetRequiredService<IVaas>();
        await vaas.Connect(CancellationToken.None);
        return (Vaas)vaas;
    }

    private static IServiceCollection GetServices(Dictionary<string, string> data)
    {
        var s = new MemoryConfigurationSource() { InitialData = data };
        var configuration = new ConfigurationBuilder()
            .Add(s)
            .Build();

        var services = new ServiceCollection();
        services.AddVerdictAsAService(configuration);
        return services;
    }

    [Fact]
    public async Task UploadEmptyFile()
    {
        await File.WriteAllBytesAsync("empty.txt", Array.Empty<byte>());
        var vaas = await AuthenticateWithCredentials();
        var result = await vaas.ForFileAsync("empty.txt", CancellationToken.None);
        Assert.Equal(Verdict.Clean, result.Verdict);
        Assert.Equal(Vaas.Sha256CheckSum("empty.txt"), result.Sha256);
    }

    [Fact]
    public async Task Connect_WithResourceOwnerPasswordGrantAuthenticator()
    {
        var services = GetServices(new Dictionary<string, string>()
        {
            { "VerdictAsAService:Url", VaasUrl.ToString() },
            { "VerdictAsAService:TokenUrl", AuthenticationEnvironment.TokenUrl.ToString() },
            { "VerdictAsAService:Credentials:GrantType", "Password" },
            { "VerdictAsAService:Credentials:ClientId", AuthenticationEnvironment.ClientIdForResourceOwnerPasswordGrant },
            { "VerdictAsAService:Credentials:UserName", AuthenticationEnvironment.UserName },
            { "VerdictAsAService:Credentials:Password", AuthenticationEnvironment.Password },
        });
        var provider = services.BuildServiceProvider();

        var vaas = provider.GetRequiredService<IVaas>();
        await vaas.Connect(CancellationToken.None);
    }

    [Fact]
    public async Task ForStream_WithEicarUrl_ReturnsMaliciousWithDetectionsAndMimeType()
    {
        var vaas = await AuthenticateWithCredentials();
        var url = new Uri("https://secure.eicar.org/eicar.com.txt");
        var response = await _httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Get, url), CancellationToken.None);
        var targetStream = await response.Content.ReadAsStreamAsync();

        var verdict = await vaas.ForStreamAsync(targetStream, CancellationToken.None);

        Assert.Equal(Verdict.Malicious, verdict.Verdict);
        Assert.Equal("text/plain", verdict.FileType);
        Assert.Equal("EICAR virus test files", verdict.MimeType);
        Assert.Contains("EICAR-Test-File", verdict.Detection);
    }

    [Fact]
    public async Task ForUrl_WithEicarUrl_ReturnsMaliciousWithDetectionAndMimeType()
    {
        var vaas = await AuthenticateWithCredentials();
        var uri = new Uri("https://secure.eicar.org/eicar.com");

        var verdict = await vaas.ForUrlAsync(uri, CancellationToken.None);

        Assert.Equal(Verdict.Malicious, verdict.Verdict);
        Assert.Equal("text/plain", verdict.FileType);
        Assert.Equal("EICAR virus test files", verdict.MimeType);
        Assert.Contains("EICAR-Test-File", verdict.Detection);
    }
}
