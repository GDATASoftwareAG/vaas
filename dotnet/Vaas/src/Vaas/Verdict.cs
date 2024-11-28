using System.Text.Json.Serialization;

namespace Vaas;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum Verdict
{
    Clean,
    Unknown,
    Malicious,
    Pup,
}
