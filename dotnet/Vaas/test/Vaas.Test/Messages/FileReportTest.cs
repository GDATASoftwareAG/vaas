using System.Text.Json;
using FluentAssertions;
using Vaas.Messages;
using Xunit;

namespace Vaas.Test.Messages;

public class FileReportTest
{
    [Fact]
    public void Deserialize_ReturnsIsEncrypted()
    {
        const string fileReportJson = """
            {"sha256":"c0621519a2dd9336b12dc6caef2cc789f23eef3026916638dcd620d0ac193881","verdict":"Clean","isEncrypted":true}
            """;

        var fileReport = JsonSerializer.Deserialize<FileReport>(
            fileReportJson,
            new JsonSerializerOptions(JsonSerializerDefaults.Web)
        );

        fileReport
            .Should()
            .BeEquivalentTo(
                new FileReport
                {
                    Sha256 = "c0621519a2dd9336b12dc6caef2cc789f23eef3026916638dcd620d0ac193881",
                    Verdict = Verdict.Clean,
                    IsEncrypted = true,
                }
            );
    }
}
