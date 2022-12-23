require 'async'
require 'async/http/endpoint'
require 'async/websocket/client'
require 'async/http/internet'
require 'json'
require 'securerandom'
require 'digest'
require 'protocol/http/body/file'
require 'uri'

require_relative 'vaas_verdict'
require_relative 'vaas_errors'

class Vaas

  attr_accessor :session_id, :websocket, :url, :connection_status

  def initialize(url="wss://gateway-vaas.gdatasecurity.de")
    @session_id = nil
    @websocket = nil
    @url = url
    @connection_status = false
  end

  def connect(token)
    endpoint = Async::HTTP::Endpoint.parse(url, alpn_protocols: Async::HTTP::Protocol::HTTP1.names)
    self.websocket = Async::WebSocket::Client.connect(endpoint)

    auth_request = JSON.generate({:kind => "AuthRequest", :token => token})
    websocket.write(auth_request)

    while message = websocket.read
      message = JSON.parse(message)
      if message['success'] == true
        self.session_id = message['session_id']
        break
      else
        raise VaasAuthenticationError
      end
    end
  end

  def get_authenticated_websocket
    raise VaasInvalidStateError if websocket == nil
    raise VaasInvalidStateError, "connect() was not awaited" if session_id == nil
    begin
      websocket.write("ping") # test connection
    rescue IOError => e # still not working
      raise VaasConnectionClosedError e.message
    end
    websocket
  end

  def close
      websocket&.close
  end

  def __for_sha256(sha256)
    websocket = get_authenticated_websocket
    guid = SecureRandom.uuid.to_s
    verdict_request =  JSON.generate({:kind => "VerdictRequest",
                                      :session_id => session_id,
                                      :sha256 => sha256,
                                      :guid => guid})
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

  def for_url(url)
    websocket = get_authenticated_websocket
    guid = SecureRandom.uuid.to_s
    url = URI(url).to_s
    verdict_request =  JSON.generate({:kind => "VerdictRequestForUrl",
                                      :session_id => session_id,
                                      :guid => guid,
                                      :url => url})
    websocket.write(verdict_request)

    while message = websocket.read
      message = JSON.parse(message)
      if message['kind'] == "VerdictResponse"
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
