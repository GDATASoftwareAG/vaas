require 'async'
require 'vaas/client_credentials_grant_authenticator'
require 'vaas/vaas_main'

CLIENT_ID = "YOUR ID"
CLIENT_SECRET = "YOUR SECRET"
PATH = "PATH FOR TEST-FILE"

def main
  authenticator = VAAS::ClientCredentialsGrantAuthenticator.new(
    CLIENT_ID,
    CLIENT_SECRET,
    "https://keycloak-vaas.gdatasecurity.de/realms/vaas/protocol/openid-connect/token"
  )

  # create a vaas object and get a token to authenticate
  vaas = VAAS::VaasMain.new
  token = authenticator.get_token

  Async do
    # wait to connect and authenticate
    Async { vaas.connect(token) }.wait

    # simple method to get the verdict of a file
    verdict = vaas.for_file(PATH)

    puts "Verdict #{verdict.sha256} is detected as #{verdict.verdict}"

  ensure
    vaas.close
  end
end

if __FILE__  == $0
  main
end
