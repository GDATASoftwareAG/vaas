#define DOCTEST_CONFIG_IMPLEMENT
#include "vaas.h"
#include "dotenv.h"
#include <doctest/doctest.h>

static char* program;

int main(int argc, char** argv) {
    program = argv[0];
    doctest::Context context;
    context.applyCommandLine(argc, argv);

    int res = context.run(); // run doctest

    // important - query flags (and --exit) rely on the user doing this
    if (context.shouldExit()) {
        // propagate the result of the tests
        return res;
    }

    return 0;
}

vaas::Vaas initVaas() {
    auto dotenv = dotenv::Dotenv();

    auto vaasUrl = dotenv.get("VAAS_URL");
    auto tokenUrl = dotenv.get("TOKEN_URL");
    auto clientId = dotenv.get("CLIENT_ID");
    auto clientSecret = dotenv.get("CLIENT_SECRET");


    // const auto vaasUrl = std::getenv("VAAS_URL")
    //                          ? std::getenv("VAAS_URL")
    //                          : "https://upload.staging.vaas.gdatasecurity.de";
    // const auto tokenUrl = std::getenv("TOKEN_URL")
    //                           ? std::getenv("TOKEN_URL")
    //                           : "https://account-staging.gdata.de/realms/vaas-staging/protocol/openid-connect/token";
    // const auto clientId = std::getenv("CLIENT_ID")
    //                           ? std::getenv("CLIENT_ID")
    //                           : throw std::runtime_error("CLIENT_ID must be set");
    // const auto clientSecret = std::getenv("CLIENT_SECRET")
    //                               ? std::getenv("CLIENT_SECRET")
    //                               : throw std::runtime_error("CLIENT_SECRET must be set");
    // 
    // Print all environment variables
    std::cout << "VAAS_URL: " << vaasUrl << std::endl;
    std::cout << "TOKEN_URL: " << tokenUrl << std::endl;
    std::cout << "CLIENT_ID: " << clientId << std::endl;
    std::cout << "CLIENT_SECRET: " << clientSecret << std::endl;
    
    return vaas::Vaas(vaasUrl, tokenUrl, clientId, clientSecret);
}

class VaasTestFixture {
protected:
    vaas::Vaas vaas;

    VaasTestFixture() : vaas(initVaas()) {
    }
};

TEST_CASE_FIXTURE(VaasTestFixture, "forFile_withCleanFile_returnsClean") {
    auto report = vaas.forFile(program);
    CHECK(report.verdict == vaas::VaasReport::Verdict::Clean);
}

/* TODO: Currently broken
TEST_CASE_FIXTURE(VaasTestFixture, "forHash_withMaliciousFile_returnsMalicious") {
    auto report = vaas.forHash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
    CHECK(report.verdict == vaas::VaasReport::Verdict::Malicious);
}
*/
