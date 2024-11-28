using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Memory;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Moq.Contrib.HttpClient;
using Vaas.Authentication;
using Vaas.Test.Authentication;
using Xunit;
using Xunit.Abstractions;

namespace Vaas.Test;

public class VaasTest
{
    private static Uri VaasUrl => new(DotNetEnv.Env.GetString(
        "VAAS_URL",
        "https://gateway.production.vaas.gdatasecurity.de"));

    private readonly ITestOutputHelper _output;
    private readonly CountingDelegatingHandler _handler = new();
    private IVaas _vaas;

    public VaasTest(ITestOutputHelper output)
    {
        _output = output;
        DotNetEnv.Env.TraversePath().Load();
        CreateVaas();
    }

    private void CreateVaas()
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        var provider = services.BuildServiceProvider();

        _vaas = provider.GetRequiredService<IVaas>();
    }
    
    private Mock<HttpMessageHandler> UseHttpMessageHandlerMock()
    {
        var handlerMock = new Mock<HttpMessageHandler>();
        _handler.InnerHandler = handlerMock.Object;
        return handlerMock;
    }

    private static IServiceCollection GetServices()
    {
        return GetServices(new Dictionary<string, string>()
        {
            { "VerdictAsAService:Url", VaasUrl.ToString() },
            { "VerdictAsAService:TokenUrl", AuthenticationEnvironment.TokenUrl.ToString() },
            { "VerdictAsAService:Credentials:GrantType", "ClientCredentials" },
            { "VerdictAsAService:Credentials:ClientId", AuthenticationEnvironment.ClientId },
            { "VerdictAsAService:Credentials:ClientSecret", AuthenticationEnvironment.ClientSecret },
            { "VerdictAsAService:UseCache", "false" }
        });
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
    
    
    // For all
    //   _SendsUserAgent
    //   _IfOptionsAreSet_SendsOptions
    //   _IfVaasRequestIdIsSet_SendsTraceState
    //   _IfVaasClientException_ThrowsVaasClientException
    //   _IfVaasServerException_ThrowsVaasServerException
    //   _IfAuthenticatorThrowsAuthenticationException_ThrowsAuthenticationException
    //   _If401_ThrowsAuthenticationException
    //   _IfCancellationRequested_ThrowsOperationCancelledException

    [Theory]
    [InlineData("110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe9", Verdict.Unknown)]
    [InlineData("cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e", Verdict.Clean)]
    [InlineData("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2", Verdict.Malicious)]
    // AMTSO
    [InlineData("d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad", Verdict.Pup)]
    public async Task ForSha256Async_ReturnsVerdict(ChecksumSha256 sha256, Verdict verdict)
    {
        var verdictResponse = await _vaas.ForSha256Async(
            sha256,
            CancellationToken.None);
        Assert.Equal(verdict, verdictResponse.Verdict);
        Assert.Equal(sha256, verdictResponse.Sha256, true);
    }

    [Fact]
    public async Task ForSha256Async_IfOptionsAreSet_SendsOptions()
    {
        ChecksumSha256 sha256 = "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e";
        var handler = UseHttpMessageHandlerMock();
        handler.SetupRequest(new Uri(VaasUrl, "")).CallBase();

        var verdictResponse = await _vaas.ForSha256Async(
            sha256,
            CancellationToken.None);
        
        handler.VerifyAll();
    }
    
    [Fact]
    public async Task ForSha256Async_SendsUserAgent()
    {
        ChecksumSha256 sha256 = "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e";
        var handler = UseHttpMessageHandlerMock();
        handler.SetupRequest(new Uri(VaasUrl, "")).CallBase();

        var verdictResponse = await _vaas.ForSha256Async(
            sha256,
            CancellationToken.None);
        
        handler.VerifyAll();
    }
    
    [Fact]
    public async Task ForSha256Async_IfVaasRequestIdIsSet_SendsTraceState()
    {
        ChecksumSha256 sha256 = "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e";
        var options = new ForSha256Options { VaasRequestId = "MyRequestId" };
        
        var verdictResponse = await _vaas.ForSha256Async(
            sha256,
            CancellationToken.None, options);
        
        throw new NotImplementedException();
    }

    [Fact]
    public async Task ForSha256Async_IfVaasClientException_ThrowsVaasClientException()
    {
        throw new NotImplementedException();
    }

    [Fact]
    public async Task ForSha256Async_IfVaasServerException_ThrowsVaasServerException()
    {
        throw new NotImplementedException();
    }
    
    [Fact]
    public async Task ForSha256Async_IfAuthenticatorThrowsAuthenticationException_ThrowsAuthenticationException()
    {
        throw new NotImplementedException();
    }
    
    [Fact]
    public async Task ForSha256Async_If401_ThrowsAuthenticationException()
    {
        throw new NotImplementedException();
    }
    
    [Fact]
    public async Task ForSha256Async_IfCancellationRequested_ThrowsOperationCancelledException()
    {
        throw new NotImplementedException();
    }

    [Fact]
    public async Task ForFileAsync_ReturnsVerdict()
    {
        throw new NotImplementedException();
        
        // var rnd = new Random();
        // var b = new byte[50];
        // rnd.NextBytes(b);
        // await File.WriteAllBytesAsync("test.txt", b);
        // var vaas = await AuthenticateWithCredentials();
        // var result = await vaas.ForFileAsync("test.txt", CancellationToken.None);
        // Assert.Equal(Verdict.Clean, result.Verdict);
        // Assert.Equal(Vaas.Sha256CheckSum("test.txt"), result.Sha256);
        //
        //
        // [Fact]
        // public async Task UploadEmptyFile()
        // {
        //     await File.WriteAllBytesAsync("empty.txt", Array.Empty<byte>());
        //     var vaas = await AuthenticateWithCredentials();
        //     var result = await vaas.ForFileAsync("empty.txt", CancellationToken.None);
        //     Assert.Equal(Verdict.Clean, result.Verdict);
        //     Assert.Equal(Vaas.Sha256CheckSum("empty.txt"), result.Sha256);
        // }
    }
    
    [Fact]
    public async Task ForStreamAsync_ReturnsVerdict()
    {
        throw new NotImplementedException();
    }
    
    [Theory]
    [InlineData("https://www.gdatasoftware.com/oem/verdict-as-a-service", Verdict.Clean)]
    [InlineData("https://secure.eicar.org/eicar.com", Verdict.Malicious)]
    public async Task ForUrlAsync_ReturnsVerdict(string url, Verdict verdict)
    {
        var actual = await _vaas.ForUrlAsync(new Uri(url), CancellationToken.None);
        Assert.Equal(verdict, actual.Verdict);
    }
}
