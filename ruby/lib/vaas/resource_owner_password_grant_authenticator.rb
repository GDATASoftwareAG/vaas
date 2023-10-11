require 'json'
require 'async'
require 'async/http/internet'

module VAAS
  class ResourceOwnerPasswordGrantAuthenticator

    attr_accessor :client_id, :token_endpoint, :token, :username, :password

    def initialize(client_id, username, password, token_endpoint = 'https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token')
      @client_id = client_id
      @username = username
      @password = password
      @token_endpoint = token_endpoint
    end

    def get_token
      Async do
        client = Async::HTTP::Internet.new

        header = [['content-type', 'application/x-www-form-urlencoded']]
        body = ["grant_type=password&client_id=#{client_id}&username=#{username}&password=#{password}"]

        response = client.post(token_endpoint, header, body)
        self.token = JSON.parse(response.read)['access_token']
      rescue => e
        raise VaasAuthenticationError, e
      ensure
        client&.close
      end
      token
    end
  end
end
