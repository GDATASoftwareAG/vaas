#include "vaas.h"
#include <iostream>
#include <string>

int main() {
    try {
        const auto vaasUrl = std::getenv("VAAS_URL")
                                 ? std::getenv("VAAS_URL")
                                 // TODO: Public API endpoint URLs?
                                 : "http://localhost:41049";
        const auto tokenUrl = std::getenv("TOKEN_URL")
                                  ? std::getenv("TOKEN_URL")
                                  : "https://account-staging.gdata.de/realms/vaas-staging/protocol/openid-connect/token";
        const auto clientId = std::getenv("CLIENT_ID")
                                  ? std::getenv("CLIENT_ID")
                                  : throw std::runtime_error("CLIENT_ID must be set");
        const auto clientSecret = std::getenv("CLIENT_SECRET")
                                      ? std::getenv("CLIENT_SECRET")
                                      : throw std::runtime_error("CLIENT_SECRET must be set");
        const auto fileToScan = std::getenv("SCAN_PATH") ? std::getenv("SCAN_PATH") : throw std::runtime_error("SCAN_PATH (a file to scan) must be set");
        vaas::Vaas vaas(vaasUrl, tokenUrl, clientId, clientSecret);
        const auto report = vaas.forFile(fileToScan);
        std::cout << report << std::endl;
    } catch (const vaas::VaasException& e) {
        // Some issue talking to VaaS, retry later
        std::cerr << "VaaS Error: " << e.what() << std::endl;
    } catch (const vaas::AuthenticationException& e) {
        // We need to check our credentials before trying again
        std::cerr << "Authentication error - check your credentials: " << e.what() << std::endl;
    } catch (const std::runtime_error& e) {
        // Other error (filesystem, critical init failure - retry with care)
        std::cerr << "Problem: " << e.what() << std::endl;
    }
    return 0;
}