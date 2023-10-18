using System.Threading.Tasks;

namespace Vaas;

public interface IAuthenticator
{
    Task<string> GetToken();
}