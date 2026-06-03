using System;
using System.Text.Json;
using FluentAssertions;
using Vaas.Messages;
using Xunit;

namespace Vaas.Test.Messages;

public class UrlReportTest
{
    [Fact]
    public void Deserialize_ReturnsIsEncrypted()
    {
        const string urlReportJson = """
            {"sha256":"79fae1ed9ff540bc286f6cc79c7fbaef323987d17e182ee20f13b0285038d8ed","verdict":"Malicious","url":"https://samples.develop.vaas.gdatasecurity.de/with-and-without-password.zip","isEncrypted":true}
            """;

        var urlReport = JsonSerializer.Deserialize<UrlReport>(
            urlReportJson,
            new JsonSerializerOptions(JsonSerializerDefaults.Web)
        );

        urlReport
            .Should()
            .BeEquivalentTo(
                new UrlReport
                {
                    Sha256 = "79fae1ed9ff540bc286f6cc79c7fbaef323987d17e182ee20f13b0285038d8ed",
                    Verdict = Verdict.Malicious,
                    Url = new Uri(
                        "https://samples.develop.vaas.gdatasecurity.de/with-and-without-password.zip"
                    ),
                    IsEncrypted = true,
                }
            );
    }
}
