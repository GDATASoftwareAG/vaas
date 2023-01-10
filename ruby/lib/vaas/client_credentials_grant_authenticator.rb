require 'json'
require 'async'
require 'async/http/internet'

module VAAS
class ClientCredentialsGrantAuthenticator

    attr_accessor :client_id, :client_secret, :token_endpoint, :token

    def initialize(client_id, client_secret, token_endpoint)
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
            p e
        ensure
            client&.close
        end
        token
    end
end
end
