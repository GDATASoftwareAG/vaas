using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Reflection;
using System.Security.Authentication;
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
using Vaas.Exceptions;
using Vaas.Messages;
using Vaas.Options;
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
    private IVaas _vaas;

    private const string EicarSha256 =
        "ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2";

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

    private static ServiceCollection GetServices()
    {
        return GetServices(
            new Dictionary<string, string>
            {
                { "VerdictAsAService:Options:UseHashLookup", "true" },
                { "VerdictAsAService:Options:UseCache", "false" },
                { "VerdictAsAService:Options:VaasUrl", VaasUrl.ToString() },
                { "VerdictAsAService:Options:Timeout", "120" },
                {
                    "VerdictAsAService:Credentials:TokenUrl",
                    AuthenticationEnvironment.TokenUrl.ToString()
                },
                {
                    "VerdictAsAService:Credentials:GrantType",
                    GrantType.ClientCredentials.ToString()
                },
                { "VerdictAsAService:Credentials:ClientId", AuthenticationEnvironment.ClientId },
                {
                    "VerdictAsAService:Credentials:ClientSecret",
                    AuthenticationEnvironment.ClientSecret
                },
            }
        );
    }

    private static ServiceCollection GetServices(Dictionary<string, string> data)
    {
        var s = new MemoryConfigurationSource { InitialData = data };
        var configuration = new ConfigurationBuilder().Add(s).Build();

        var services = new ServiceCollection();
        services.AddVerdictAsAService(configuration);
        return services;
    }

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
    [InlineData("d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad", Verdict.Pup)]
    public async Task ForSha256Async_ReturnsVerdict(string sha256, Verdict verdict)
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
    public async Task ForSha256Async_SendsOptions(bool useCache, bool useHashLookup)
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
            .ReturnsResponse(
                JsonSerializer.Serialize(
                    new FileReport { Sha256 = EicarSha256, Verdict = Verdict.Clean }
                )
            );
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

    [Fact]
    public async Task ForSha256Async_IfVaasRequestIdIsSet_SendsTraceState()
    {
        ChecksumSha256 sha256 = "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e";

        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);

        var handlerMock = new Mock<HttpMessageHandler>();
        const string requestId = "foobar";
        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null
                && request.RequestUri.ToString().Contains(sha256)
                && request
                    .RequestUri.ToString()
                    .Contains("useCache=" + JsonSerializer.Serialize(true))
                && request
                    .RequestUri.ToString()
                    .Contains("useHashLookup=" + JsonSerializer.Serialize(true))
                && request.Headers.GetValues("tracestate").Contains($"vaasrequestid={requestId}")
            )
            .ReturnsResponse(
                JsonSerializer.Serialize(
                    new FileReport { Sha256 = EicarSha256, Verdict = Verdict.Unknown }
                )
            );
        services
            .AddHttpClient<IVaas, Vaas>()
            .ConfigurePrimaryHttpMessageHandler(() => handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();
        var sha256Options = new ForSha256Options { VaasRequestId = requestId };

        await vaas.ForSha256Async(sha256, CancellationToken.None, sha256Options);

        handlerMock.VerifyAll();
    }

    [Fact]
    public async Task ForSha256Async_IfVaasClientException_ThrowsVaasClientException()
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);

        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null && request.RequestUri.ToString().Contains(EicarSha256)
            )
            .ReturnsResponse(
                statusCode: HttpStatusCode.BadRequest,
                configure: message =>
                {
                    message.Content = JsonContent.Create(
                        new ProblemDetails
                        {
                            Detail = "Mocked client-side error",
                            Type = "VaasClientException",
                        }
                    );
                }
            );
        services
            .AddHttpClient<IVaas, Vaas>()
            .ConfigurePrimaryHttpMessageHandler(() => handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();

        await vaas.Invoking(async v => await v.ForSha256Async(EicarSha256, CancellationToken.None))
            .Should()
            .ThrowAsync<VaasClientException>();
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
                request.RequestUri != null && request.RequestUri.ToString().Contains(EicarSha256)
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

        await vaas.Invoking(async v => await v.ForSha256Async(EicarSha256, CancellationToken.None))
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

        await vaas.Invoking(async v => await v.ForSha256Async(EicarSha256, CancellationToken.None))
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
                request.RequestUri != null && request.RequestUri.ToString().Contains(EicarSha256)
            )
            .ReturnsResponse(HttpStatusCode.Unauthorized);
        services
            .AddHttpClient<IVaas, Vaas>()
            .ConfigurePrimaryHttpMessageHandler(() => handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();

        await vaas.Invoking(async v => await v.ForSha256Async(EicarSha256, CancellationToken.None))
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
            .Invoking(async v => await v.ForSha256Async(EicarSha256, ct))
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
        var fileName = Guid.NewGuid() + ".txt";
        await File.WriteAllBytesAsync(fileName, Encoding.UTF8.GetBytes(content));

        var actual = await _vaas.ForFileAsync(fileName, CancellationToken.None);

        File.Delete(fileName);

        Assert.Equal(verdict, actual.Verdict);
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
        var fileName = Guid.NewGuid() + ".txt";

        await File.WriteAllBytesAsync(fileName, Encoding.UTF8.GetBytes(content));

        var handlerMock = new Mock<HttpMessageHandler>(MockBehavior.Strict);

        if (useCache || useHashLookup)
        {
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
                    JsonSerializer.Serialize(
                        new FileReport { Sha256 = EicarSha256, Verdict = Verdict.Unknown }
                    )
                );
        }

        if (!useCache)
        {
            handlerMock
                .SetupRequest(request =>
                    request.RequestUri != null
                    && request.Method == HttpMethod.Get
                    && request.RequestUri.ToString().Contains(sha256)
                    && request
                        .RequestUri.ToString()
                        .Contains("useCache=" + JsonSerializer.Serialize(true))
                    && request
                        .RequestUri.ToString()
                        .Contains("useHashLookup=" + JsonSerializer.Serialize(useHashLookup))
                )
                .ReturnsResponse(
                    JsonSerializer.Serialize(
                        new FileReport { Sha256 = EicarSha256, Verdict = Verdict.Unknown }
                    )
                );
        }

        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null
                && request.Method == HttpMethod.Post
                && request.RequestUri.ToString().Contains("/files")
                && request
                    .RequestUri.ToString()
                    .Contains("useHashLookup=" + JsonSerializer.Serialize(useHashLookup))
            )
            .ReturnsResponse(JsonSerializer.Serialize(new FileAnalysisStarted { Sha256 = sha256 }));
        services
            .AddHttpClient<IVaas, Vaas>()
            .ConfigurePrimaryHttpMessageHandler(() => handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();

        await vaas.ForFileAsync(
            fileName,
            CancellationToken.None,
            new ForFileOptions { UseCache = useCache, UseHashLookup = useHashLookup }
        );
        File.Delete(fileName);

        handlerMock.VerifyAll();
    }

    [Fact]
    public async Task ForFileAsync_IfVaasRequestIdIsSet_SendsTraceState()
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        const string content =
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        const string sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        await File.WriteAllBytesAsync("file.txt", Encoding.UTF8.GetBytes(content));

        var handlerMock = new Mock<HttpMessageHandler>();
        const string requestId = "foobar";
        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null
                && request.RequestUri.ToString().Contains(sha256)
                && request
                    .RequestUri.ToString()
                    .Contains("useCache=" + JsonSerializer.Serialize(true))
                && request
                    .RequestUri.ToString()
                    .Contains("useHashLookup=" + JsonSerializer.Serialize(true))
                && request.Headers.GetValues("tracestate").Contains($"vaasrequestid={requestId}")
            )
            .ReturnsResponse(
                JsonSerializer.Serialize(
                    new FileReport { Sha256 = EicarSha256, Verdict = Verdict.Unknown }
                )
            );

        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null
                && request.Method == HttpMethod.Post
                && request.RequestUri.ToString().Contains("/files")
                && request
                    .RequestUri.ToString()
                    .Contains("useHashLookup=" + JsonSerializer.Serialize(true))
            )
            .ReturnsResponse(JsonSerializer.Serialize(new FileAnalysisStarted { Sha256 = sha256 }));
        services
            .AddHttpClient<IVaas, Vaas>()
            .ConfigurePrimaryHttpMessageHandler(() => handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();
        var forFileOptions = new ForFileOptions() { VaasRequestId = requestId };

        await vaas.ForFileAsync("file.txt", CancellationToken.None, forFileOptions);

        handlerMock.VerifyAll();
    }

    [Fact]
    public async Task ForFileAsync_IfVaasClientException_ThrowsVaasClientException()
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        const string content =
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        await File.WriteAllBytesAsync("file.txt", Encoding.UTF8.GetBytes(content));

        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null && request.RequestUri.ToString().Contains("/files")
            )
            .ReturnsResponse(
                statusCode: HttpStatusCode.BadRequest,
                configure: message =>
                {
                    message.Content = JsonContent.Create(
                        new ProblemDetails
                        {
                            Detail = "Mocked client-side error",
                            Type = "VaasClientException",
                        }
                    );
                }
            );
        services
            .AddHttpClient<IVaas, Vaas>()
            .ConfigurePrimaryHttpMessageHandler(() => handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();

        await vaas.Invoking(async v => await v.ForFileAsync("file.txt", CancellationToken.None))
            .Should()
            .ThrowAsync<VaasClientException>();
    }

    [Theory]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.GatewayTimeout)]
    [InlineData(HttpStatusCode.HttpVersionNotSupported)]
    [InlineData(HttpStatusCode.BadGateway)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    public async Task ForFileAsync_IfVaasServerException_ThrowsVaasServerException(
        HttpStatusCode serverError
    )
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        const string content =
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        await File.WriteAllBytesAsync("file.txt", Encoding.UTF8.GetBytes(content));

        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null && request.RequestUri.ToString().Contains("/files")
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

        await vaas.Invoking(async v => await v.ForFileAsync("file.txt", CancellationToken.None))
            .Should()
            .ThrowAsync<VaasServerException>();
    }

    [Fact]
    public async Task ForFileAsync_IfAuthenticatorThrowsAuthenticationException_ThrowsAuthenticationException()
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        const string content =
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        await File.WriteAllBytesAsync("file.txt", Encoding.UTF8.GetBytes(content));

        var handlerMock = new Mock<IAuthenticator>();
        handlerMock
            .Setup(a => a.GetTokenAsync(CancellationToken.None))
            .Throws<AuthenticationException>();
        services.RemoveAll<IAuthenticator>();
        services.AddSingleton(handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();

        await vaas.Invoking(async v => await v.ForFileAsync("file.txt", CancellationToken.None))
            .Should()
            .ThrowAsync<AuthenticationException>();
    }

    [Fact]
    public async Task ForFileAsync_If401_ThrowsAuthenticationException()
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        const string content =
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        await File.WriteAllBytesAsync("file.txt", Encoding.UTF8.GetBytes(content));

        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null && request.RequestUri.ToString().Contains("/files")
            )
            .ReturnsResponse(HttpStatusCode.Unauthorized);
        services
            .AddHttpClient<IVaas, Vaas>()
            .ConfigurePrimaryHttpMessageHandler(() => handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();

        await vaas.Invoking(async v => await v.ForFileAsync("file.txt", CancellationToken.None))
            .Should()
            .ThrowAsync<VaasAuthenticationException>();
    }

    [Fact]
    public async Task ForFileAsync_IfCancellationRequested_ThrowsOperationCancelledException()
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        const string content =
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        await File.WriteAllBytesAsync("file.txt", Encoding.UTF8.GetBytes(content));

        var ct = new CancellationToken(true);

        await _vaas
            .Invoking(async v => await v.ForFileAsync("file.txt", ct))
            .Should()
            .ThrowAsync<OperationCanceledException>();
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
    [InlineData(false)]
    [InlineData(true)]
    public async Task ForStreamOptions_SendsOptions(bool useHashLookup)
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        var targetStream = new MemoryStream(
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"u8.ToArray()
        );

        var handlerMock = new Mock<HttpMessageHandler>(MockBehavior.Strict);

        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null
                && request.Method == HttpMethod.Get
                && request.RequestUri.ToString().Contains(EicarSha256)
                && request
                    .RequestUri.ToString()
                    .Contains("useCache=" + JsonSerializer.Serialize(true))
                && request
                    .RequestUri.ToString()
                    .Contains("useHashLookup=" + JsonSerializer.Serialize(useHashLookup))
            )
            .ReturnsResponse(
                JsonSerializer.Serialize(
                    new FileReport { Sha256 = EicarSha256, Verdict = Verdict.Unknown }
                )
            );

        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null
                && request.Method == HttpMethod.Post
                && request.RequestUri.ToString().Contains("/files")
                && request
                    .RequestUri.ToString()
                    .Contains("useHashLookup=" + JsonSerializer.Serialize(useHashLookup))
            )
            .ReturnsResponse(
                JsonSerializer.Serialize(new FileAnalysisStarted { Sha256 = EicarSha256 })
            );
        services
            .AddHttpClient<IVaas, Vaas>()
            .ConfigurePrimaryHttpMessageHandler(() => handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();

        await vaas.ForStreamAsync(
            targetStream,
            CancellationToken.None,
            new ForStreamOptions { UseHashLookup = useHashLookup }
        );

        handlerMock.VerifyAll();
    }

    [Fact]
    public async Task ForStreamAsync_SendsUserAgent()
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        var targetStream = new MemoryStream(
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"u8.ToArray()
        );

        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null
                && request
                    .Headers.UserAgent.ToString()
                    .Contains("Cs/" + Assembly.GetAssembly(typeof(Vaas))?.GetName().Version)
            )
            .ReturnsResponse(
                JsonSerializer.Serialize(
                    new FileReport { Sha256 = EicarSha256, Verdict = Verdict.Unknown }
                )
            );

        services
            .AddHttpClient<IVaas, Vaas>()
            .ConfigurePrimaryHttpMessageHandler(() => handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();

        var verdict = await vaas.ForStreamAsync(targetStream, CancellationToken.None);
        _output.WriteLine(verdict.ToString());

        handlerMock.VerifyAll();
    }

    [Fact]
    public async Task ForStreamAsync_IfVaasRequestIdIsSet_SendsTraceState()
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        var targetStream = new MemoryStream(
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"u8.ToArray()
        );

        var handlerMock = new Mock<HttpMessageHandler>();
        const string requestId = "foobar";
        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null
                && request.RequestUri.ToString().Contains(EicarSha256)
                && request
                    .RequestUri.ToString()
                    .Contains("useCache=" + JsonSerializer.Serialize(true))
                && request
                    .RequestUri.ToString()
                    .Contains("useHashLookup=" + JsonSerializer.Serialize(true))
                && request.Headers.GetValues("tracestate").Contains($"vaasrequestid={requestId}")
            )
            .ReturnsResponse(
                JsonSerializer.Serialize(
                    new FileReport { Sha256 = EicarSha256, Verdict = Verdict.Unknown }
                )
            );

        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null
                && request.Method == HttpMethod.Post
                && request.RequestUri.ToString().Contains("/files")
                && request
                    .RequestUri.ToString()
                    .Contains("useHashLookup=" + JsonSerializer.Serialize(true))
            )
            .ReturnsResponse(
                JsonSerializer.Serialize(new FileAnalysisStarted { Sha256 = EicarSha256 })
            );
        services
            .AddHttpClient<IVaas, Vaas>()
            .ConfigurePrimaryHttpMessageHandler(() => handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();
        var forStreamOptions = new ForStreamOptions() { VaasRequestId = requestId };

        await vaas.ForStreamAsync(targetStream, CancellationToken.None, forStreamOptions);

        handlerMock.VerifyAll();
    }

    [Fact]
    public async Task ForStreamAsync_IfVaasClientException_ThrowsVaasClientException()
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        var targetStream = new MemoryStream(
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"u8.ToArray()
        );

        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null && request.RequestUri.ToString().Contains("/files")
            )
            .ReturnsResponse(
                statusCode: HttpStatusCode.BadRequest,
                configure: message =>
                {
                    message.Content = JsonContent.Create(
                        new ProblemDetails
                        {
                            Detail = "Mocked client-side error",
                            Type = "VaasClientException",
                        }
                    );
                }
            );
        services
            .AddHttpClient<IVaas, Vaas>()
            .ConfigurePrimaryHttpMessageHandler(() => handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();

        await vaas.Invoking(async v => await v.ForStreamAsync(targetStream, CancellationToken.None))
            .Should()
            .ThrowAsync<VaasClientException>();
    }

    [Theory]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.GatewayTimeout)]
    [InlineData(HttpStatusCode.HttpVersionNotSupported)]
    [InlineData(HttpStatusCode.BadGateway)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    public async Task ForStreamAsync_IfVaasServerException_ThrowsVaasServerException(
        HttpStatusCode serverError
    )
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        var targetStream = new MemoryStream(
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"u8.ToArray()
        );

        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null && request.RequestUri.ToString().Contains("/files")
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

        await vaas.Invoking(async v => await v.ForStreamAsync(targetStream, CancellationToken.None))
            .Should()
            .ThrowAsync<VaasServerException>();
    }

    [Fact]
    public async Task ForStreamAsync_IfAuthenticatorThrowsAuthenticationException_ThrowsAuthenticationException()
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        var targetStream = new MemoryStream(
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"u8.ToArray()
        );

        var handlerMock = new Mock<IAuthenticator>();
        handlerMock
            .Setup(a => a.GetTokenAsync(CancellationToken.None))
            .Throws<AuthenticationException>();
        services.RemoveAll<IAuthenticator>();
        services.AddSingleton(handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();

        await vaas.Invoking(async v => await v.ForStreamAsync(targetStream, CancellationToken.None))
            .Should()
            .ThrowAsync<AuthenticationException>();
    }

    [Fact]
    public async Task ForStreamAsync_If401_ThrowsAuthenticationException()
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        var targetStream = new MemoryStream(
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"u8.ToArray()
        );

        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null && request.RequestUri.ToString().Contains("/files")
            )
            .ReturnsResponse(HttpStatusCode.Unauthorized);
        services
            .AddHttpClient<IVaas, Vaas>()
            .ConfigurePrimaryHttpMessageHandler(() => handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();

        await vaas.Invoking(async v => await v.ForStreamAsync(targetStream, CancellationToken.None))
            .Should()
            .ThrowAsync<VaasAuthenticationException>();
    }

    [Fact]
    public async Task ForStreamAsync_IfCancellationRequested_ThrowsOperationCancelledException()
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        var targetStream = new MemoryStream(
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"u8.ToArray()
        );

        var ct = new CancellationToken(true);

        await _vaas
            .Invoking(async v => await v.ForStreamAsync(targetStream, ct))
            .Should()
            .ThrowAsync<OperationCanceledException>();
    }

    [Theory]
    [InlineData("https://www.gdatasoftware.com/oem/verdict-as-a-service", Verdict.Clean)]
    [InlineData("https://secure.eicar.org/eicar.com", Verdict.Malicious)]
    public async Task ForUrlAsync_ReturnsVerdict(string url, Verdict verdict)
    {
        var actual = await _vaas.ForUrlAsync(new Uri(url), CancellationToken.None);
        Assert.Equal(verdict, actual.Verdict);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ForUrlOptions_SendsOptions(bool useHashLookup)
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        var url = new Uri("https://secure.eicar.org/eicar.com");
        var urlAnalysisStarted = new UrlAnalysisStarted { Id = Guid.NewGuid().ToString() };

        var handlerMock = new Mock<HttpMessageHandler>(MockBehavior.Strict);

        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null
                && request.Method == HttpMethod.Get
                && request.RequestUri.ToString().Contains(urlAnalysisStarted.Id)
            )
            .ReturnsResponse(
                JsonSerializer.Serialize(
                    new UrlReport
                    {
                        Sha256 = EicarSha256,
                        Verdict = Verdict.Unknown,
                        Url = url,
                    }
                )
            );

        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null
                && request.Method == HttpMethod.Post
                && request.RequestUri.ToString().Contains("/urls")
            )
            .ReturnsResponse(JsonSerializer.Serialize(urlAnalysisStarted));
        services
            .AddHttpClient<IVaas, Vaas>()
            .ConfigurePrimaryHttpMessageHandler(() => handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();

        await vaas.ForUrlAsync(
            url,
            CancellationToken.None,
            new ForUrlOptions { UseHashLookup = useHashLookup }
        );

        handlerMock.VerifyAll();
    }

    [Fact]
    public async Task ForUrlAsync_SendsUserAgent()
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        var url = new Uri("https://secure.eicar.org/eicar.com");
        var urlAnalysisStarted = new UrlAnalysisStarted { Id = Guid.NewGuid().ToString() };

        var handlerMock = new Mock<HttpMessageHandler>();

        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null
                && request.Method == HttpMethod.Get
                && request.RequestUri.ToString().Contains(urlAnalysisStarted.Id)
                && request.Headers.UserAgent.ToString()
                    == new ProductInfoHeaderValue(
                        "Cs",
                        Assembly.GetAssembly(typeof(Vaas))?.GetName().Version?.ToString()
                    ).ToString()
            )
            .ReturnsResponse(
                JsonSerializer.Serialize(
                    new UrlReport
                    {
                        Sha256 = EicarSha256,
                        Verdict = Verdict.Unknown,
                        Url = url,
                    }
                )
            );

        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null
                && request.Method == HttpMethod.Post
                && request.RequestUri.ToString().Contains("/urls")
                && request.Headers.UserAgent.ToString()
                    == new ProductInfoHeaderValue(
                        "Cs",
                        Assembly.GetAssembly(typeof(Vaas))?.GetName().Version?.ToString()
                    ).ToString()
            )
            .ReturnsResponse(JsonSerializer.Serialize(urlAnalysisStarted));
        services
            .AddHttpClient<IVaas, Vaas>()
            .ConfigurePrimaryHttpMessageHandler(() => handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();

        await vaas.ForUrlAsync(url, CancellationToken.None);

        handlerMock.VerifyAll();
    }

    [Fact]
    public async Task ForUrlAsync_IfVaasRequestIdIsSet_SendsTraceState()
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        var url = new Uri("https://secure.eicar.org/eicar.com");
        var urlAnalysisStarted = new UrlAnalysisStarted { Id = Guid.NewGuid().ToString() };

        var handlerMock = new Mock<HttpMessageHandler>();
        const string requestId = "foobar";
        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null
                && request.Method == HttpMethod.Get
                && request.RequestUri.ToString().Contains(urlAnalysisStarted.Id)
                && request.Headers.GetValues("tracestate").Contains($"vaasrequestid={requestId}")
            )
            .ReturnsResponse(
                JsonSerializer.Serialize(
                    new UrlReport
                    {
                        Sha256 = EicarSha256,
                        Verdict = Verdict.Unknown,
                        Url = url,
                    }
                )
            );

        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null
                && request.Method == HttpMethod.Post
                && request.RequestUri.ToString().Contains("/urls")
                && request.Headers.GetValues("tracestate").Contains($"vaasrequestid={requestId}")
            )
            .ReturnsResponse(JsonSerializer.Serialize(urlAnalysisStarted));
        services
            .AddHttpClient<IVaas, Vaas>()
            .ConfigurePrimaryHttpMessageHandler(() => handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();
        var forUrlOptions = new ForUrlOptions() { VaasRequestId = requestId };

        await vaas.ForUrlAsync(url, CancellationToken.None, forUrlOptions);

        handlerMock.VerifyAll();
    }

    [Fact]
    public async Task ForUrlAsync_IfVaasClientException_ThrowsVaasClientException()
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        var url = new Uri("https://secure.eicar.org/eicar.com");

        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null
                && request.Method == HttpMethod.Post
                && request.RequestUri.ToString().Contains("/urls")
            )
            .ReturnsResponse(
                statusCode: HttpStatusCode.BadRequest,
                configure: message =>
                {
                    message.Content = JsonContent.Create(
                        new ProblemDetails
                        {
                            Detail = "Mocked client-side error",
                            Type = "VaasClientException",
                        }
                    );
                }
            );

        services
            .AddHttpClient<IVaas, Vaas>()
            .ConfigurePrimaryHttpMessageHandler(() => handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();

        await vaas.Invoking(async v => await v.ForUrlAsync(url, CancellationToken.None))
            .Should()
            .ThrowAsync<VaasClientException>();
    }

    [Theory]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.GatewayTimeout)]
    [InlineData(HttpStatusCode.HttpVersionNotSupported)]
    [InlineData(HttpStatusCode.BadGateway)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    public async Task ForUrlAsync_IfVaasServerException_ThrowsVaasServerException(
        HttpStatusCode serverError
    )
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        var url = new Uri("https://secure.eicar.org/eicar.com");

        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null
                && request.Method == HttpMethod.Post
                && request.RequestUri.ToString().Contains("/urls")
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

        await vaas.Invoking(async v => await v.ForUrlAsync(url, CancellationToken.None))
            .Should()
            .ThrowAsync<VaasServerException>();
    }

    [Fact]
    public async Task ForUrlAsync_IfAuthenticatorThrowsAuthenticationException_ThrowsAuthenticationException()
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        var url = new Uri("https://secure.eicar.org/eicar.com");

        var handlerMock = new Mock<IAuthenticator>();
        handlerMock
            .Setup(a => a.GetTokenAsync(CancellationToken.None))
            .Throws<AuthenticationException>();
        services.RemoveAll<IAuthenticator>();
        services.AddSingleton(handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();

        await vaas.Invoking(async v => await v.ForUrlAsync(url, CancellationToken.None))
            .Should()
            .ThrowAsync<AuthenticationException>();
    }

    [Fact]
    public async Task ForUrlAsync_If401_ThrowsAuthenticationException()
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        var url = new Uri("https://secure.eicar.org/eicar.com");

        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock
            .SetupRequest(request =>
                request.RequestUri != null
                && request.Method == HttpMethod.Post
                && request.RequestUri.ToString().Contains("/urls")
            )
            .ReturnsResponse(HttpStatusCode.Unauthorized);
        services
            .AddHttpClient<IVaas, Vaas>()
            .ConfigurePrimaryHttpMessageHandler(() => handlerMock.Object);
        var provider = services.BuildServiceProvider();
        var vaas = provider.GetRequiredService<IVaas>();

        await vaas.Invoking(async v => await v.ForUrlAsync(url, CancellationToken.None))
            .Should()
            .ThrowAsync<VaasAuthenticationException>();
    }

    [Fact]
    public async Task ForUrlAsync_IfCancellationRequested_ThrowsOperationCancelledException()
    {
        var services = GetServices();
        ServiceCollectionTools.Output(_output, services);
        var url = new Uri("https://secure.eicar.org/eicar.com");

        var ct = new CancellationToken(true);

        await _vaas
            .Invoking(async v => await v.ForUrlAsync(url, ct))
            .Should()
            .ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task ForFile_WithTimeout_ThrowsException()
    {
        var authenticator = new ClientCredentialsGrantAuthenticator(
            AuthenticationEnvironment.ClientId,
            AuthenticationEnvironment.ClientSecret,
            AuthenticationEnvironment.TokenUrl
        );
        var options = new VaasOptions
        {
            Timeout = TimeSpan.FromSeconds(1),
            UseCache = false,
            UseHashLookup = false,
            VaasUrl = new Uri("https://gateway.staging.vaas.gdatasecurity.de"),
        };
        var vaas = new Vaas(authenticator, options);

        try
        {
            var random100Mb = new byte[1000 * 1024 * 1024];
            new Random().NextBytes(random100Mb);
            await File.WriteAllBytesAsync("file.txt", random100Mb);
            await vaas.Invoking(async v => await v.ForFileAsync("file.txt", CancellationToken.None))
                .Should()
                .ThrowAsync<TaskCanceledException>();
        }
        finally
        {
            File.Delete("file.txt");
        }
    }
}
