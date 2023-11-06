using System.Threading;
using System.Threading.Tasks;

namespace Vaas.Authentication;

public interface IAuthenticator
{
    Task<string> GetTokenAsync(CancellationToken cancellationToken);
}
