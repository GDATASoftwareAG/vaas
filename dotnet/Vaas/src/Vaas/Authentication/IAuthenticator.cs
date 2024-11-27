using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;

namespace Vaas.Authentication;

public interface IAuthenticator
{
    /// <exception cref="AuthenticationException">Authentication failed.</exception>
    Task<string> GetTokenAsync(CancellationToken cancellationToken);
}
