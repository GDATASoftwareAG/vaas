using System;

namespace Vaas.Authentication;

public interface ISystemClock
{
    DateTimeOffset UtcNow { get; }
}

public class SystemClock : ISystemClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}