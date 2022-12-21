require 'async'
require 'async/http/endpoint'
require 'async/websocket/client'
require 'async/http/internet'
require 'json'
require 'securerandom'
require 'digest'
require 'protocol/http/body/file'

require_relative 'vaas_verdict'

URL = "wss://gateway-vaas.gdatasecurity.de"



class Vaas

  attr_accessor :session_id, :connection

  def initialize
    @session_id = nil
    @connection = nil
  end


  def connect(token)

      endpoint = Async::HTTP::Endpoint.parse(URL, alpn_protocols: Async::HTTP::Protocol::HTTP11.names)
      self.connection = Async::WebSocket::Client.connect(endpoint)
      authenticate(token)

  end

  def authenticate(token)
    auth_request = JSON.generate({:kind => "AuthRequest", :token => "#{token}"})
    connection.write(auth_request)

    while message = connection.read
      message = JSON.parse(message)
      if message['kind'] == "AuthResponse"
        self.session_id = message['session_id']
        break
      end

    end
  end

  def for_sha256(sha256)
    verdict_request =  JSON.generate({:kind => "VerdictRequest", :session_id => "#{session_id}", :sha256 => "#{sha256}", :guid => "#{SecureRandom.uuid}"})
    connection.write(verdict_request)

    while message = connection.read
      message = JSON.parse(message)
      if message['kind'] == "VerdictResponse"
        return VaasVerdict.new(message)
      end
    end
  end

  def for_file(path)
    sha256 = Digest::SHA256.file(path).hexdigest
    verdict_request =  JSON.generate({:kind => "VerdictRequest", :session_id => "#{session_id}", :sha256 => "#{sha256}", :guid => "#{SecureRandom.uuid}"})
    connection.write(verdict_request)

    while message = connection.read
      message = JSON.parse(message)
      if message['kind'] == "VerdictResponse" and message['verdict'] != "Unknown"
        return VaasVerdict.new(message)
      elsif message['kind'] == "VerdictResponse" and message['verdict'] == "Unknown"
        upload(message, path)
      else
        p message
      end
    end
  end

  def upload (message, path)
    token = message['upload_token']
    url = message['url']

    Async do
      client = Async::HTTP::Internet.new

      header = [['authorization', token]]
      body = Protocol::HTTP::Body::File.open(File.join(path))

      response = client.put(url, header, body)
      p response.status
    rescue => e
      p e
    ensure
      client&.close
    end
  end

end
