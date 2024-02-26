#include "cxx.h"
#include "vaas.rs.h"
#include "dotenv.h"
#include <iostream>

int main(int argc, const char **argv) {
    dotenv env{argc, argv, true, {
            dotenv::in_current_folder(),
            dotenv::in_program_folder(),
            "../.env"
    }};

    auto client_id = env.get("CLIENT_ID", "");
    auto client_secret = env.get("CLIENT_SECRET", "");
    auto token_url = env.get("TOKEN_URL", "");
    auto vaas_url = env.get("VAAS_URL", "");

    if (client_id.empty() || client_secret.empty())
        throw std::invalid_argument("CLIENT_ID or CLIENT_SECRET not set");

    auto creds = vaas::new_client_credentials(client_id, client_secret);
    if (!token_url.empty())
        creds->with_token_url(token_url);
    auto builder = vaas::new_builder_from_client_credentials(*creds);
    if (!vaas_url.empty())
        builder->url(vaas_url);
    auto vaas = builder->build();

    auto connection = vaas->connect();
    auto ct = vaas::new_cancellation_token_from_seconds(20);
    auto verdict = connection->for_file("../eicar.com.txt", *ct);
    std::cout << "sha256 verdict " << verdict.sha256 << std::endl;
    std::cout << "verdict " << static_cast<int>(verdict.verdict) << std::endl;
    return 0;
}