using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using CommunityToolkit.Diagnostics;

namespace Vaas;

[JsonConverter(typeof(ChecksumSha256Converter))]
public class ChecksumSha256
{
    private const string EmptyFileSha256 =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    public string Sha256 { get; }
    private static readonly Regex Pattern = new("^[a-fA-F0-9]{64}$", RegexOptions.Compiled);

    public ChecksumSha256(string sha256)
    {
        if (!Pattern.IsMatch(sha256))
        {
            throw new ArgumentException("Invalid Sha256", nameof(sha256));
        }
        Sha256 = sha256.ToLower();
    }

    public ChecksumSha256(byte[] sha256)
    {
        Guard.HasSizeEqualTo(sha256, 32);
        Sha256 = Convert.ToHexString(sha256).ToLower();
    }

    public bool IsEmptyFile()
    {
        return Sha256 == EmptyFileSha256;
    }

    public static bool TryParse(string value, out ChecksumSha256? result)
    {
        try
        {
            result = new ChecksumSha256(value);
            return true;
        }
        catch (ArgumentException)
        {
            result = default;
            return false;
        }
    }

    public static implicit operator ChecksumSha256(string sha256) => new(sha256);

    public static implicit operator string(ChecksumSha256 s) => s.Sha256;

    public override string ToString() => Sha256;
}

public class ChecksumSha256Converter : JsonConverter<ChecksumSha256>
{
    public override ChecksumSha256? Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options
    )
    {
        return new ChecksumSha256(
            reader.GetString() ?? throw new JsonException("Expected SHA256 string")
        );
    }

    public override void Write(
        Utf8JsonWriter writer,
        ChecksumSha256 value,
        JsonSerializerOptions options
    )
    {
        writer.WriteStringValue(value.ToString());
    }
}
