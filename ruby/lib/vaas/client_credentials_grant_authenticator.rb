require 'json'
require 'async'
require 'async/http/internet'

module VAAS
  class ClientCredentialsGrantAuthenticator

    attr_accessor :client_id, :client_secret, :token_endpoint, :token

    def initialize(client_id, client_secret, token_endpoint = 'https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token')
      @client_id = client_id
      @client_secret = client_secret
      @token_endpoint = token_endpoint
    end

    def get_token
      Async do
        client = Async::HTTP::Internet.new

        header = [['content-type', 'application/x-www-form-urlencoded']]
        body = ["grant_type=client_credentials&client_id=#{client_id}&client_secret=#{client_secret}"]

        response = client.post(token_endpoint, header, body)
        self.token = JSON.parse(response.read)['access_token']
      rescue => e
        raise VaasAuthenticationError, e
      ensure
        client&.close
      end

      raise VaasAuthenticationError if token.nil?
      token
    end
  end
end
