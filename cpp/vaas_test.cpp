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

vaas::OIDCClient initAuthenticator() {
    auto dotenv = dotenv::Dotenv();
    const auto tokenUrl = dotenv.get("TOKEN_URL");
    const auto clientId = dotenv.get("CLIENT_ID");
    const auto clientSecret = dotenv.get("CLIENT_SECRET");
    return vaas::OIDCClient(tokenUrl, clientId, clientSecret);
}

vaas::Vaas initVaas() {
    auto dotenv = dotenv::Dotenv();
    auto vaasUrl = dotenv.get("VAAS_URL");
    
    auto authenticator = initAuthenticator();
    return vaas::Vaas(vaasUrl, std::move(authenticator));
}

class VaasTestFixture {
  protected:
    vaas::Vaas vaas;

    VaasTestFixture() : vaas(initVaas()) {
    }
};

class AuthenticatorTestFixture {
  protected:
    vaas::OIDCClient authenticator;

    AuthenticatorTestFixture() : authenticator(initAuthenticator()) {
    }
};

TEST_CASE_FIXTURE(AuthenticatorTestFixture, "OIDCClient::getAccessToken_withValidCredentials_returnsToken") {
    auto token = authenticator.getAccessToken();
    CHECK(!token.empty());
}

TEST_CASE("OIDCClient::getAccessToken_withGarbageCredentials_throwsAuthenticationException") {
    const auto tokenUrl = std::getenv("TOKEN_URL")
                              ? std::getenv("TOKEN_URL")
                              : "https://account-staging.gdata.de/realms/vaas-staging/protocol/openid-connect/token";
    const auto clientId = std::getenv("CLIENT_ID")
                              ? std::getenv("CLIENT_ID")
                              : "auth-test-client-id";
    // Intentionally incorrect credentials
    auto authenticator = vaas::OIDCClient(tokenUrl, clientId, "incorrect-client-secret");
    CHECK_THROWS_WITH_AS(authenticator.getAccessToken(), "Invalid client or Invalid client credentials", vaas::AuthenticationException);
}

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
