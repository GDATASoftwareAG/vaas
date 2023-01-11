require 'async'
require 'vaas/client_credentials_grant_authenticator'
require 'vaas/vaas_main'

CLIENT_ID = "YOUR ID"
CLIENT_SECRET = "YOUR SECRET"
PATHS = "LIST OF PATHS FOR TEST-FILES"

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

    # simple loop to get the verdict of a list of files
    PATHS.each do |file|
      verdict = vaas.for_file(file)
      puts "Verdict #{verdict.sha256} is detected as #{verdict.verdict}"
    end

  ensure
    vaas.close
  end
end

if __FILE__  == $0
  main
end
