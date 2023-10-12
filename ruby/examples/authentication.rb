require 'vaas/client_credentials_grant_authenticator'
require 'vaas/resource_owner_password_grant_authenticator'


def main
    client_id = ENV.fetch("CLIENT_ID") || "vaas-customer"
    client_secret = ENV.fetch("CLIENT_SECRET")
    user_name = ENV.fetch("VAAS_USER_NAME")
    password = ENV.fetch("VAAS_PASSWORD")
    token_url = ENV.fetch("TOKEN_URL") || "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"
    vaas_url = ENV.fetch("VAAS_URL") || "wss://gateway.production.vaas.gdatasecurity.de"
    test_url = "https://gdata.de"

    #If you got a username and password from us, you can use the ResourceOwnerPasswordAuthenticator like this
    authenticator = VAAS::ResourceOwnerPasswordGrantAuthenticator.new(
      client_id,
      user_name,
      password,
      token_url
    )
    # You may use self registration and create a new username and password for the
    # ResourceOwnerPasswordAuthenticator by yourself like the example above on https:#vaas.gdata.de/login

    # Else if you got a client id and client secret from us, you can use the ClientCredentialsGrantAuthenticator like this
    # authenticator = VAAS::ClientCredentialsGrantAuthenticator.new(
    #   client_id,
    #   client_secret,
    #   token_url
    # )


    vaas = VAAS::VaasMain.new(vaas_url)
    token = authenticator.get_token

    Async do
        vaas.connect(token)

        verdict = vaas.for_url(test_url)
        puts "Verdict #{verdict.wait.sha256} is detected as #{verdict.wait.verdict}"

        vaas.close
    end
end


if __FILE__  == $0
    main
end