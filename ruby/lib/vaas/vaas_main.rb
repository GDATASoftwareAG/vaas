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

module VAAS
  class VaasMain

    attr_accessor :session_id, :websocket, :url

    def initialize(url="wss://gateway-vaas.gdatasecurity.de")
      @url = url
    end

    def connect(token)
      # connect to endpoint
      endpoint = Async::HTTP::Endpoint.parse(url, alpn_protocols: Async::HTTP::Protocol::HTTP1.names)
      self.websocket = Async::WebSocket::Client.connect(endpoint)

      # send authentication request
      auth_request = JSON.generate({:kind => "AuthRequest", :token => token})
      websocket.write(auth_request)
      websocket.flush

      # receive authentication message
      begin
        message = websocket.read
      rescue EOFError
        raise VaasTimeoutError, "Timed out while authenticating"
      end
      message = JSON.parse(message)
      if message['success'] == true
        self.session_id = message['session_id']
      else
        raise VaasAuthenticationError
      end
    end

    def get_authenticated_websocket
      raise VaasInvalidStateError unless websocket
      raise VaasInvalidStateError, "connect() was not awaited" unless session_id
      raise VaasConnectionClosedError if websocket.closed?
      websocket
    end

    def close
        websocket&.close
    end

    def __for_sha256(sha256_list)
      # send verdict requests with a list of sha256s
      websocket = get_authenticated_websocket
      sha256_list = [sha256_list] if sha256_list.is_a? String

      sha256_list.each do |sha256|
        guid = SecureRandom.uuid.to_s
        verdict_request =  JSON.generate({:kind => "VerdictRequest",
                                          :session_id => session_id,
                                          :sha256 => sha256,
                                          :guid => guid})
        websocket.write(verdict_request)
      end
      websocket.flush

      # receive verdict messages
      messages = []
      sha256_list.size.times do
        begin
          message = websocket.read
        rescue EOFError
          warn "Timed out while reading"
          break
        end
        message = JSON.parse(message)
        if message['kind'] == "VerdictResponse"
          messages.append(message)
        else
          redo
        end
      end
      messages
    end

    def for_sha256(sha256_list)
      messages = __for_sha256(sha256_list)
      messages.map { |message|  VaasVerdict.new(message)}
    end

    def for_file(path_list)
      # get sha256s of files and send verdict requests
      file_hash = {}
      path_list = [path_list] if path_list.is_a? String
      path_list.each { |path| file_hash[Digest::SHA256.file(path).hexdigest] = path}
      messages = __for_sha256(file_hash.keys)

      # upload files if verdict is unknown
      upload_count = 0
      messages.each do |message|
        if message['verdict'] == 'Unknown'
          upload(message, file_hash[message['sha256']])
          upload_count += 1
        end
      end

      # read messages of uploaded files
      upload_count.times do
        begin
          message = websocket.read
        rescue EOFError
          warn "Timed out while reading"
          break
        end
        message = JSON.parse(message)
        if message['kind'] == "VerdictResponse"
          messages = messages.map {|m| m['guid'] == message['guid'] ? message : m }
        else
          redo
        end
      end
      messages.map { |message|  VaasVerdict.new(message)}
    end

    def for_url(url_list)
      #send verdict request with a list of urls
      websocket = get_authenticated_websocket
      url_list = [url_list] if url_list.is_a? String

      url_list.each do |url|
        guid = SecureRandom.uuid.to_s
        verdict_request =  JSON.generate({:kind => "VerdictRequestForUrl",
                                          :session_id => session_id,
                                          :guid => guid,
                                          :url => url})
        websocket.write(verdict_request)
      end
      websocket.flush

      # receive verdict messages
      verdicts = []
      url_list.size.times do
        begin
          message = websocket.read
        rescue EOFError
          warn "Timed out while reading"
          break
        end
        message = JSON.parse(message)
        if message['kind'] == "VerdictResponse"
          verdicts.append(VaasVerdict.new(message))
        else
          redo
        end
      end
      verdicts
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
end
