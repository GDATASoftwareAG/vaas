using System;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Moq;
using Moq.Contrib.HttpClient;
using Vaas.Authentication;
using Vaas.Messages;
using Xunit;

namespace Vaas.Test;

public class VaasTest
{
    private readonly ChecksumSha256 _maliciousChecksum256 =
        new("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8");

    private readonly HttpClient _httpClient;
    private readonly Mock<HttpMessageHandler> _handler;
    private readonly Mock<IAuthenticator> _authenticator;
    private readonly Vaas _vaas;

    public VaasTest()
    {
        _handler = new Mock<HttpMessageHandler>();
        _httpClient = _handler.CreateClient();
        _authenticator = new Mock<IAuthenticator>();
        _vaas = new Vaas(_httpClient, _authenticator.Object, new VaasOptions());
    }

    [Fact]
    public async Task ForSha256Async_SendsUserAgent()
    {
        const string productName = "VaaS_C#_SDK";
        var productVersion = Assembly.GetAssembly(typeof(Vaas))?.GetName().Version?.ToString() ?? "0.0.0";
        _handler.SetupRequest(r => r.Headers.UserAgent.ToString() == $"{productName}/{productVersion}")
            .ReturnsResponse(JsonSerializer.Serialize(new VerdictResponse(_maliciousChecksum256, Verdict.Malicious)));

        var verdict = await _vaas.ForSha256Async(_maliciousChecksum256, CancellationToken.None);

        Assert.Equal(Verdict.Malicious, verdict.Verdict);
    }

    [Fact]
    public void Constructor_IfRelativeUrl_ThrowsVaasClientException()
    {
        var e = Assert.Throws<ArgumentException>(() =>
            new Vaas(_httpClient, _authenticator.Object, new VaasOptions() { Url = new Uri("/relative") }));
        Assert.Equal(
            "Parameter \"options.Url.Host\" (string) must not be null or whitespace, was whitespace. (Parameter 'options.Url.Host')",
            e.Message);
    }

    [Theory]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.NotFound)]
    public async Task ForSha256Async_OnClientError_ThrowsVaasClientException(HttpStatusCode statusCode)
    {
        _handler.SetupAnyRequest()
            .ReturnsResponse(statusCode);

        var e = await Assert.ThrowsAsync<VaasClientException>(() =>
            _vaas.ForSha256Async(_maliciousChecksum256, CancellationToken.None));
        Assert.Equal("Client-side error", e.Message);
    }

    [Theory]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.BadGateway)]
    [InlineData(HttpStatusCode.GatewayTimeout)]
    public async Task ForSha256Async_OnServerError_ThrowsVaasServerError(HttpStatusCode statusCode)
    {
        _handler.SetupAnyRequest()
            .ReturnsResponse(statusCode);

        var e = await Assert.ThrowsAsync<VaasServerException>(() =>
            _vaas.ForSha256Async(_maliciousChecksum256, CancellationToken.None));
        Assert.Equal("Server-side error", e.Message);
    }

    [Fact]
    public async Task ForSha256Async_IfNullIsReturned_ThrowsVaasServerError()
    {
        _handler.SetupAnyRequest()
            .ReturnsResponse("null");

        var e = await Assert.ThrowsAsync<VaasServerException>(() =>
            _vaas.ForSha256Async(_maliciousChecksum256, CancellationToken.None));
        Assert.Equal("Server returned 'null'", e.Message);
    }

    [Fact]
    public async Task ForSha256Async_OnJsonException_ThrowsVaasServerException()
    {
        _handler.SetupAnyRequest()
            .ReturnsResponse("{");

        var e = await Assert.ThrowsAsync<VaasServerException>(() =>
            _vaas.ForSha256Async(_maliciousChecksum256, CancellationToken.None));
        Assert.Equal("Server-side error", e.Message);
    }

    [Fact]
    public async Task ForSha256Async_OnSha256Null_ThrowsVaasServerException()
    {
        _handler.SetupAnyRequest()
            .ReturnsResponse("{}");

        var e = await Assert.ThrowsAsync<VaasServerException>(() =>
            _vaas.ForSha256Async(_maliciousChecksum256, CancellationToken.None));
        Assert.Equal("Server-side error", e.Message);
    }
}