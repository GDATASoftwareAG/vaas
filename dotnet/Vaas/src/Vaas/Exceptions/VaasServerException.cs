using System;

namespace Vaas.Exceptions;

/// <summary>The server encountered an internal error.</summary>
/// <remarks>
/// Recommended actions:
/// <ul>
///   <li>You may retry the request after a certain delay.</li>
///   <li>If the problem persists contact G DATA.</li>
/// </ul>
/// </remarks>
public class VaasServerException : Exception
{
    public VaasServerException(string? message)
        : base(message) { }

    public VaasServerException(string? message, Exception? innerException)
        : base(message, innerException) { }
}
