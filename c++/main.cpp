#include "vaas.h"
#include <iostream>
#include <string>

int main() {
    try {
        auto vaasUrl = std::getenv("VAAS_URL")
                           ? std::getenv("VAAS_URL")
                           : "http://localhost:42175";
        auto tokenUrl = std::getenv("TOKEN_URL")
                            ? std::getenv("TOKEN_URL")
                            : "https://account-staging.gdata.de/realms/vaas-staging/protocol/openid-connect/token";
        auto clientId = std::getenv("CLIENT_ID")
                            ? std::getenv("CLIENT_ID")
                            : throw std::runtime_error("CLIENT_ID must be set");
        auto clientSecret = std::getenv("CLIENT_SECRET")
                                ? std::getenv("CLIENT_SECRET")
                                : throw std::runtime_error("CLIENT_SECRET must be set");
        Vaas vaas(vaasUrl, tokenUrl, clientId, clientSecret);
        vaas.forFile("/home/max/eicar.com.txt");
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return 0;
}

int mainOld() {
    try {
        auto vaasUrl = std::getenv("VAAS_URL")
                           ? std::getenv("VAAS_URL")
                           : "http://localhost:42175";
        auto tokenUrl = std::getenv("TOKEN_URL")
                            ? std::getenv("TOKEN_URL")
                            : "https://account-staging.gdata.de/realms/vaas-staging/protocol/openid-connect/token";
        auto clientId = std::getenv("CLIENT_ID")
                            ? std::getenv("CLIENT_ID")
                            : throw std::runtime_error("CLIENT_ID must be set");
        auto clientSecret = std::getenv("CLIENT_SECRET")
                                ? std::getenv("CLIENT_SECRET")
                                : throw std::runtime_error("CLIENT_SECRET must be set");
        OIDCClient client(tokenUrl, clientId, clientSecret);
        std::string token = client.getAccessToken();
        std::cout << "Access Token: " << token << std::endl;
        std::string tokenAgain = client.getAccessToken();
        std::cout << "Access Token (again - reused): " << tokenAgain << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}