require 'async'
require 'async/http/endpoint'
require 'async/websocket/client'
require 'async/http/internet'
require 'json'
require 'securerandom'
require 'digest'
require 'protocol/http/body/file'

require_relative 'vaas_verdict'
require_relative 'vaas_errors'

class Vaas

  attr_accessor :session_id, :websocket, :url, :connection_status

  def initialize
    @session_id = nil
    @websocket = nil
    @url = "wss://gateway-vaas.gdatasecurity.de"
    @connection_status = false
  end

  def connect(token)
    endpoint = Async::HTTP::Endpoint.parse(url, alpn_protocols: Async::HTTP::Protocol::HTTP11.names)
    self.websocket = Async::WebSocket::Client.connect(endpoint)


    auth_request = JSON.generate({:kind => "AuthRequest", :token => "#{token}"})
    websocket.write(auth_request)

    while message = websocket.read
      message = JSON.parse(message)
      if message['success'] == true
        self.session_id = message['session_id']
        self.connection_status = true
        break
      else
        raise VaasAuthenticationError
      end
    end
  end

  def get_authenticated_websocket
      raise VaasInvalidStateError if websocket == nil
      raise VaasConnectionClosedError "connection closed or connect() was not awaited" unless connection_status
      raise VaasConnectionClosedError, "connect() was not awaited" if session_id == nil
      websocket
  end

  def close
      websocket&.close
      self.websocket = nil
  end

  def __for_sha256(sha256)
    websocket = get_authenticated_websocket
    guid = SecureRandom.uuid
    verdict_request =  JSON.generate({:kind => "VerdictRequest",
                                      :session_id => "#{session_id}",
                                      :sha256 => "#{sha256}",
                                      :guid => "#{guid}"})
    websocket.write(verdict_request)

    while message = websocket.read
      message = JSON.parse(message)
      if message['kind'] == "VerdictResponse"
        return message
      end
    end
  end

  def for_sha256(sha256)
    response = __for_sha256(sha256)
    VaasVerdict.new(response)
  end

  def for_file(path)
    sha256 = Digest::SHA256.file(path).hexdigest
    response = __for_sha256(sha256)
    if response['verdict'] == 'Unknown'
      upload(response, path)
    else
      return VaasVerdict.new(response)
    end

    while message = websocket.read
      message = JSON.parse(message)
      if message['kind'] == "VerdictResponse" and message['verdict'] != "Unknown"
        return VaasVerdict.new(message)
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

      client.put(url, header, body).read

    rescue => e
      raise VaasUploadError, e
    ensure
      client&.close
    end
  end

end
