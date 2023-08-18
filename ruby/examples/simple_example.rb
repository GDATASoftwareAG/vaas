require 'async'
require 'vaas/client_credentials_grant_authenticator'
require 'vaas/vaas_main'

CLIENT_ID = ENV.fetch('CLIENT_ID')
CLIENT_SECRET = ENV.fetch('CLIENT_SECRET')
VAAS_URL = ENV.fetch('VAAS_URL', "wss://gateway.production.vaas.gdatasecurity.de")
TOKEN_URL = ENV.fetch('TOKEN_URL', 'https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token')

URL = ENV.fetch('URL')

def main
  authenticator = VAAS::ClientCredentialsGrantAuthenticator.new(
    CLIENT_ID,
    CLIENT_SECRET,
    TOKEN_URL
  )

  # create a vaas object and get a token to authenticate
  vaas = VAAS::VaasMain.new(VAAS_URL)
  token = authenticator.get_token

  Async do
    vaas.connect(token)

    verdict = vaas.for_url(URL)
    puts "Verdict #{verdict.wait.sha256} is detected as #{verdict.wait.verdict}"

    vaas.close
  end
end

if __FILE__  == $0
  main
end
