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
