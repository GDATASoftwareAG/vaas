require 'async'

require_relative '../src/client_credentials_grant_authenticator'
require_relative '../src/vaas'

CLIENT_ID = "YOUR ID"
CLIENT_SECRET = "YOUR SECRET"
PATH = "PATH FOR TEST-FILE"

def main
  authenticator = ClientCredentialsGrantAuthenticator.new(
    CLIENT_ID,
    CLIENT_SECRET,
    "https://keycloak-vaas.gdatasecurity.de/realms/vaas/protocol/openid-connect/token"
  )

  vaas = Vaas.new
  token = authenticator.get_token

  auth_task = Async do
    vaas.connect(token)
  end

  auth_task.wait
  Async do
    result2 = vaas.for_file(PATH)
    puts "Verdict #{result2.sha256} is detected as #{result2.verdict}"
  end

ensure
  Async do
    vaas.close
  end
end

if __FILE__  == $0
  main
end
