using System;

namespace Vaas.Exceptions;

/// <summary>The request is malformed or cannot be completed.</summary>
/// <remarks>
/// Recommended actions:
/// <ul>
///   <li>Don't repeat the request.</li>
///   <li>Log.</li>
///   <li>Analyze the error</li>
/// </ul>
/// </remarks>
public class VaasClientException : Exception
{
    public VaasClientException(string? message)
        : base(message) { }

    public VaasClientException(string? message, Exception? innerException)
        : base(message, innerException) { }
}
