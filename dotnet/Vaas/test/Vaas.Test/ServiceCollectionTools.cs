using System;
using System.Linq;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace Vaas.Test;

public static class ServiceCollectionTools
{
    public static void Output(ITestOutputHelper output, IServiceCollection services)
    {
        var sortedServices = services.OrderBy(d => d.ServiceType.Name);
        foreach (var s in sortedServices)
        {
            output.WriteLine(
                $"{GetNameWithTypeParameters(s.ServiceType)} {GetImplementationName(s)}"
            );
        }
    }

    private static string GetImplementationName(ServiceDescriptor s)
    {
        if (s.ImplementationType != null)
        {
            return $"type {GetNameWithTypeParameters(s.ImplementationType)}";
        }

        if (s.ImplementationInstance != null)
        {
            return $"instance";
        }

        if (s.ImplementationFactory != null)
        {
            return $"factory {s.ImplementationFactory.Method.Module.Name} {s.ImplementationFactory}";
        }

        throw new ArgumentException("Unknown type of service descriptor", nameof(s));
    }

    private static string GetNameWithTypeParameters(Type type)
    {
        if (!type.IsGenericType)
            return type.Name;

        string genericArguments = type.GetGenericArguments()
            .Select(x => x.Name)
            .Aggregate((x1, x2) => $"{x1}, {x2}");
        var indexOfBacktick = type.Name.IndexOf("`", StringComparison.InvariantCulture);
        if (indexOfBacktick == -1)
        {
            return type.Name;
        }
        return $"{type.Name.Substring(0, indexOfBacktick)}" + $"<{genericArguments}>";
    }
}
