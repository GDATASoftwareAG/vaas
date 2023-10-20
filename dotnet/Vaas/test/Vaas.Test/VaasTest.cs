using System;
using System.Net;
using System.Threading.Tasks;
using Xunit;

namespace Vaas.Test;

public class VaasTest
{
    [Fact]
    public Task ForSha256Async_SendsUserAgent()
    {
        throw new NotImplementedException();
    }
    
    [Fact]
    public Task ForSha256Async_IfRelativeUrl_ThrowsVaasClientException()
    {
        throw new NotImplementedException();
    }
    
    [Theory]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.NotFound)]
    public Task ForSha256Async_OnClientError_ThrowsVaasClientException(HttpStatusCode statusCode)
    {
        throw new NotImplementedException();
    }

    [Theory]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.BadGateway)]
    [InlineData(HttpStatusCode.GatewayTimeout)]
    public Task ForSha256Async_OnServerError_ThrowsVaasServerError(HttpStatusCode statusCode)
    {
        throw new NotImplementedException();
    }
    
    [Fact]
    public Task ForSha256Async_IfNullIsReturned_ThrowsVaasServerError()
    {
        throw new NotImplementedException();
    }
}