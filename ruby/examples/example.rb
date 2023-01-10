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

  vaas = VAAS::VaasMain.new
  token = authenticator.get_token

  Async do
    Async { vaas.connect(token) }.wait

    result = vaas.for_file(PATH)

    puts "Verdict #{result.sha256} is detected as #{result.verdict}"

  ensure
    vaas.close
  end
end

if __FILE__  == $0
  main
end
