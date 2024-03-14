using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;
using CommunityToolkit.Diagnostics;

namespace Vaas.Messages;

public class VerdictResponse
{
    public VerdictResponse(string sha256, Verdict verdict)
    {
        Guard.IsNotNull(sha256);
        Guard.IsNotNull(verdict);
        Sha256 = sha256;
        Verdict = verdict;
    }

    [JsonPropertyName("kind")]
    public string Kind { get; init; } = "VerdictResponse";

    [JsonPropertyName("sha256")]
    public string? Sha256 { get; init; }

    [JsonPropertyName("guid")]
    public string? Guid { get; init; }

    [JsonPropertyName("verdict")]
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public Verdict Verdict { get; init; }

    [JsonPropertyName("url")]
    public string? Url { get; init; }

    [JsonPropertyName("upload_token")]
    public string? UploadToken { get; init; }

    [JsonPropertyName("detections")]
    public List<Detection>? Detections { get; init; }

    [JsonPropertyName("lib_magic")]
    public LibMagic? LibMagic { get; init; }

    [MemberNotNullWhen(true, nameof(Sha256), nameof(Guid))]
    public bool IsValid => !string.IsNullOrWhiteSpace(Sha256)
                           && !string.IsNullOrWhiteSpace(Guid);
}