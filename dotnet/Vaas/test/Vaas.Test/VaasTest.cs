using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Moq;
using Moq.Contrib.HttpClient;
using Vaas.Authentication;
using Vaas.Messages;
using Vaas.Test.Authentication;
using Xunit;
using Xunit.Abstractions;

namespace Vaas.Test;

public class VaasTest
{
    private static Uri VaasUrl =>
        new(
            DotNetEnv.Env.GetString("VAAS_URL", "https://gateway.production.vaas.gdatasecurity.de")
        );

    private readonly ITestOutputHelper _output;
    private readonly CountingDelegatingHandler _handler = new();
    private IVaas _vaas;

    public string eicarSha256 = "ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2";

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
        return GetServices(
            new Dictionary<string, string>
            {
                { "VerdictAsAService:Url", VaasUrl.ToString() },
                { "VerdictAsAService:TokenUrl", AuthenticationEnvironment.TokenUrl.ToString() },
                {
                    "VerdictAsAService:Credentials:GrantType",
                    GrantType.ClientCredentials.ToString()
                },
                { "VerdictAsAService:Credentials:ClientId", AuthenticationEnvironment.ClientId },
                {
                    "VerdictAsAService:Credentials:ClientSecret",
                    AuthenticationEnvironment.ClientSecret
                },
                { "VerdictAsAService:UseCache", "false" },
            }
        );
    }

    private static ServiceCollection GetServices(Dictionary<string, string> data)
    {
        var s = new MemoryConfigurationSource() { InitialData = data };
        var configuration = new ConfigurationBuilder().Add(s).Build();

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
    [InlineData(
        "110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe9",
        Verdict.Unknown
    )]
    [InlineData("cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e", Verdict.Clean)]
    [InlineData(
        "ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2",
        Verdict.Malicious
    )]
    // AMTSO
    [InlineData("d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad", Verdict.Pup)]
    public async Task ForSha256Async_ReturnsVerdict(ChecksumSha256 sha256, Verdict verdict)
    {
        var verdictResponse = await _vaas.ForSha256Async(sha256, CancellationToken.None);
        Assert.Equal(verdict, verdictResponse.Verdict);
        Assert.Equal(sha256, verdictResponse.Sha256, true);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task ForSha256Options_SendsOptions(bool useCache, bool useHashLookup)
    {
        ChecksumSha256 sha256 = "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e";

        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);

        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null
                && request.RequestUri.ToString().Contains(sha256)
                && request
                    .RequestUri.ToString()
                    .Contains("useCache=" + JsonSerializer.Serialize(useCache))
                && request
                    .RequestUri.ToString()
                    .Contains("useHashLookup=" + JsonSerializer.Serialize(useHashLookup))
            )
            .ReturnsResponse(JsonSerializer.Serialize(new VerdictResponse(sha256, Verdict.Clean)));
        services
            .AddHttpClient<IVaas, Vaas>()
            .ConfigurePrimaryHttpMessageHandler(() => handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();

        await vaas.ForSha256Async(
            sha256,
            CancellationToken.None,
            new ForSha256Options { UseCache = useCache, UseHashLookup = useHashLookup }
        );

        handlerMock.VerifyAll();
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task ForFileOptions_SendsOptions(bool useCache, bool useHashLookup)
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        const string content =
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        const string sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        await File.WriteAllBytesAsync("file.txt", Encoding.UTF8.GetBytes(content));

        var handlerMock = new Mock<HttpMessageHandler>(MockBehavior.Strict);
        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null
                && request.Method == HttpMethod.Get
                && request.RequestUri.ToString().Contains(sha256)
                && request
                    .RequestUri.ToString()
                    .Contains("useCache=" + JsonSerializer.Serialize(useCache))
                && request
                    .RequestUri.ToString()
                    .Contains("useHashLookup=" + JsonSerializer.Serialize(useHashLookup))
            )
            .ReturnsResponse(
                JsonSerializer.Serialize(new VerdictResponse(sha256, Verdict.Malicious))
            );
        services
            .AddHttpClient<IVaas, Vaas>()
            .ConfigurePrimaryHttpMessageHandler(() => handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();

        await vaas.ForFileAsync(
            "file.txt",
            CancellationToken.None,
            new ForFileOptions { UseCache = useCache, UseHashLookup = useHashLookup }
        );

        handlerMock.VerifyAll();
    }

    [Fact]
    public async Task ForSha256Async_SendsUserAgent()
    {
        ChecksumSha256 sha256 = "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e";
        var handler = UseHttpMessageHandlerMock();
        handler.SetupRequest(new Uri(VaasUrl, "")).CallBase();

        var verdictResponse = await _vaas.ForSha256Async(sha256, CancellationToken.None);

        handler.VerifyAll();
    }

    [Fact]
    public async Task ForSha256Async_IfVaasRequestIdIsSet_SendsTraceState()
    {
        ChecksumSha256 sha256 = "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e";
        var options = new ForSha256Options { VaasRequestId = "MyRequestId" };

        var verdictResponse = await _vaas.ForSha256Async(sha256, CancellationToken.None, options);

        throw new NotImplementedException();
    }

    [Fact]
    public async Task ForSha256Async_IfVaasClientException_ThrowsVaasClientException()
    {
        throw new NotImplementedException();
    }

    [Theory]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.GatewayTimeout)]
    [InlineData(HttpStatusCode.HttpVersionNotSupported)]
    [InlineData(HttpStatusCode.BadGateway)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    public async Task ForSha256Async_IfVaasServerException_ThrowsVaasServerException(
        HttpStatusCode serverError
    )
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);

        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null && request.RequestUri.ToString().Contains(eicarSha256)
            )
            .ReturnsResponse(
                statusCode: serverError,
                configure: message =>
                {
                    message.Content = JsonContent.Create(
                        new ProblemDetails
                        {
                            Detail = "Mocked server-side error",
                            Type = "VaasServerException",
                        }
                    );
                }
            );
        services
            .AddHttpClient<IVaas, Vaas>()
            .ConfigurePrimaryHttpMessageHandler(() => handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();

        await vaas.Invoking(async v => await v.ForSha256Async(eicarSha256, CancellationToken.None))
            .Should()
            .ThrowAsync<VaasServerException>();
    }

    [Fact]
    public async Task ForSha256Async_IfAuthenticatorThrowsAuthenticationException_ThrowsAuthenticationException()
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);

        var handlerMock = new Mock<IAuthenticator>();
        handlerMock
            .Setup(a => a.GetTokenAsync(CancellationToken.None))
            .Throws<AuthenticationException>();
        services.RemoveAll<IAuthenticator>();
        services.AddSingleton(handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();

        await vaas.Invoking(async v => await v.ForSha256Async(eicarSha256, CancellationToken.None))
            .Should()
            .ThrowAsync<AuthenticationException>();
    }

    [Fact]
    public async Task ForSha256Async_If401_ThrowsAuthenticationException()
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);

        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null && request.RequestUri.ToString().Contains(eicarSha256)
            )
            .ReturnsResponse(HttpStatusCode.Unauthorized);
        services
            .AddHttpClient<IVaas, Vaas>()
            .ConfigurePrimaryHttpMessageHandler(() => handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();

        await vaas.Invoking(async v => await v.ForSha256Async(eicarSha256, CancellationToken.None))
            .Should()
            .ThrowAsync<VaasAuthenticationException>();
    }

    [Fact]
    public async Task ForSha256Async_IfCancellationRequested_ThrowsOperationCancelledException()
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        var ct = new CancellationToken(true);

        await _vaas
            .Invoking(async v => await v.ForSha256Async(eicarSha256, ct))
            .Should()
            .ThrowAsync<OperationCanceledException>();
    }

    [Theory]
    [InlineData("", Verdict.Clean)]
    [InlineData("foobar", Verdict.Clean)]
    [InlineData(
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        Verdict.Malicious
    )]
    public async Task ForFileAsync_ReturnsVerdict(string content, Verdict verdict)
    {
        await File.WriteAllBytesAsync("file.txt", Encoding.UTF8.GetBytes(content));

        var actual = await _vaas.ForFileAsync("file.txt", CancellationToken.None);

        Assert.Equal(verdict, actual.Verdict);
    }

    [Fact]
    public async Task ForFileAsync_IfForSha256DoesNotReturnDetectionEtc_UploadsFile()
    {
        var buffer = new byte[1024];
        Random.Shared.NextBytes(buffer);
        await File.WriteAllBytesAsync("file.txt", buffer);
        var sha256 = new ChecksumSha256(SHA256.HashData(buffer));
        // TODO: Mock response

        var actual = await _vaas.ForFileAsync("file.txt", CancellationToken.None);

        actual
            .Should()
            .BeEquivalentTo(
                new VaasVerdict
                {
                    Sha256 = sha256,
                    Detection = null,
                    FileType = "data",
                    MimeType = "application/octet-stream",
                }
            );
    }

    [Fact]
    public async Task ForStreamAsync_ReturnsVerdict()
    {
        var targetStream = new MemoryStream(
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"u8.ToArray()
        );

        var verdict = await _vaas.ForStreamAsync(targetStream, CancellationToken.None);

        Assert.Equal(Verdict.Malicious, verdict.Verdict);
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
