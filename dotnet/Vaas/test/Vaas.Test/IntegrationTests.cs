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
    private static Uri VaasUrl =>
        new Uri(
            DotNetEnv.Env.GetString("VAAS_URL", "wss://gateway.production.vaas.gdatasecurity.de")
        );

    private readonly ITestOutputHelper _output;
    private readonly HttpClient _httpClient = new();

    public IntegrationTests(ITestOutputHelper output)
    {
        _output = output;
        DotNetEnv.Env.TraversePath().Load();
    }

    [Fact]
    public async Task ForUrl_WithUrlWithStatusCode4xx_ThrowsVaasClientException()
    {
        var vaas = await AuthenticateWithCredentials();
        var e = await Assert.ThrowsAsync<VaasClientException>(
            () =>
                vaas.ForUrlAsync(
                    new Uri(
                        "https://gateway.production.vaas.gdatasecurity.de/swagger/nocontenthere"
                    ),
                    CancellationToken.None
                )
        );
        Assert.Equal(
            "Call failed with status code 404 (Not Found): GET https://gateway.production.vaas.gdatasecurity.de/swagger/nocontenthere",
            e.Message
        );
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
        var response = await _httpClient.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, url),
            CancellationToken.None
        );
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
        var response = await _httpClient.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, url),
            CancellationToken.None
        );
        var targetStream = await response.Content.ReadAsStreamAsync();

        // Act
        var verdict = await vaas.ForStreamAsync(targetStream, CancellationToken.None);

        // Assert
        Assert.Equal(Verdict.Malicious, verdict.Verdict);
    }

    private async Task<Vaas> AuthenticateWithCredentials()
    {
        var services = GetServices(
            new Dictionary<string, string>()
            {
                { "VerdictAsAService:Url", VaasUrl.ToString() },
                { "VerdictAsAService:TokenUrl", AuthenticationEnvironment.TokenUrl.ToString() },
                { "VerdictAsAService:Credentials:GrantType", "ClientCredentials" },
                { "VerdictAsAService:Credentials:ClientId", AuthenticationEnvironment.ClientId },
                {
                    "VerdictAsAService:Credentials:ClientSecret",
                    AuthenticationEnvironment.ClientSecret
                },
                { "VerdictAsAService:UseCache", "false" },
            }
        );
        // ServiceCollectionTools.Output(_output, services);
        var provider = services.BuildServiceProvider();

        var vaas = provider.GetRequiredService<IVaas>();
        return (Vaas)vaas;
    }

    private static IServiceCollection GetServices(Dictionary<string, string> data)
    {
        var s = new MemoryConfigurationSource() { InitialData = data };
        var configuration = new ConfigurationBuilder().Add(s).Build();

        var services = new ServiceCollection();
        services.AddVerdictAsAService(configuration);
        return services;
    }

    [Fact]
    public async Task ForStream_WithEicarUrl_ReturnsMaliciousWithDetectionsAndMimeType()
    {
        var vaas = await AuthenticateWithCredentials();
        var url = new Uri("https://secure.eicar.org/eicar.com.txt");
        var response = await _httpClient.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, url),
            CancellationToken.None
        );
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
