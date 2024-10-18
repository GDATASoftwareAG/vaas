#include "vaas.h"
#include <filesystem>
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " [PATH]..." << std::endl;
        exit(1);
    }

    const auto vaasUrl = std::getenv("VAAS_URL")
                             ? std::getenv("VAAS_URL")
                             : "https://gateway.staging.vaas.gdatasecurity.de";
    const auto tokenUrl = std::getenv("TOKEN_URL")
                              ? std::getenv("TOKEN_URL")
                              : "https://account-staging.gdata.de/realms/vaas-staging/protocol/openid-connect/token";
    const auto clientId = std::getenv("CLIENT_ID")
                              ? std::getenv("CLIENT_ID")
                              : throw std::runtime_error("CLIENT_ID must be set");
    const auto clientSecret = std::getenv("CLIENT_SECRET")
                                  ? std::getenv("CLIENT_SECRET")
                                  : throw std::runtime_error("CLIENT_SECRET must be set");

    try {
        vaas::Vaas vaas(vaasUrl, tokenUrl, clientId, clientSecret);

        for (int i = 1; i < argc; ++i) {
            std::filesystem::path fileOrDirectory(argv[i]);

            if (std::filesystem::is_directory(fileOrDirectory)) {
                for (const auto& entry : std::filesystem::recursive_directory_iterator(fileOrDirectory)) {
                    if (entry.is_regular_file()) {
                        const auto report = vaas.forFile(entry);
                        std::cout << entry << " " << report << std::endl;
                    }
                }
            } else {
                const auto report = vaas.forFile(fileOrDirectory);
                std::cout << fileOrDirectory << " " << report << std::endl;
            }
        }
    } catch (const vaas::VaasException& e) {
        // Some issue talking to VaaS, retry later
        std::cerr << "VaaS error: " << e.what() << std::endl;
    } catch (const vaas::AuthenticationException& e) {
        // We need to check our credentials before trying again
        std::cerr << "Authentication error - check your credentials: " << e.what() << std::endl;
    } catch (const std::runtime_error& e) {
        // Other error (filesystem, critical init failure - retry with care)
        std::cerr << "Problem: " << e.what() << std::endl;
    }
    return 0;
}