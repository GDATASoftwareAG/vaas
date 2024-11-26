using System.Threading;
using System.Threading.Tasks;

namespace Vaas.Authentication;

public interface IAuthenticator
{
    /// <exception cref="AuthenticationException"></exception>
    Task<string> GetTokenAsync(CancellationToken cancellationToken);
}
