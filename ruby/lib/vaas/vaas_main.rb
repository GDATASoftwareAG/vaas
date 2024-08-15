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

    def initialize(url = "wss://gateway.production.vaas.gdatasecurity.de", timeout = 600)
      @url = url
      @timeout = timeout
      @requests = {}
    end

    def connect(token)
      # connect to endpoint
      endpoint = Async::HTTP::Endpoint.parse(@url, alpn_protocols: Async::HTTP::Protocol::HTTP1.names)
      @websocket = Async::WebSocket::Client.connect(endpoint)

      read_messages
      keep_alive

      # send authentication request
      auth_task = Async do |task|
        task.with_timeout(@timeout) do
          @auth_notification = Async::Notification.new
          auth_request = JSON.generate({:kind => "AuthRequest", :token => token})
          @websocket.write(auth_request)
          @websocket.flush
          @auth_notification.wait
        rescue Async::TimeoutError
          close
          raise VaasTimeoutError
        end
      end

      message = auth_task.wait
      raise VaasAuthenticationError if message['success'] == false
      @session_id = message['session_id']
    end

    def keep_alive
      @keep_alive_task = Async do
        until @websocket.closed?
          sleep 10
          @websocket.send_ping
          @websocket.flush
        end
      end
    end

    def read_messages
      @read_task = Async do |task|
        task.with_timeout(@timeout) do
          while message = @websocket.read
            message = JSON.parse(message)
            if message['kind'] == "AuthResponse"
              @auth_notification.signal(message)
            elsif message['kind'] == "VerdictResponse"
              @requests[message['guid']].signal(message)
            end
          end
        rescue Async::TimeoutError
          close
          raise VaasTimeoutError
        end
      end
    end

    def get_authenticated_websocket
      raise VaasInvalidStateError unless @websocket
      raise VaasInvalidStateError, "connect() was not awaited" unless @session_id
      raise VaasConnectionClosedError if @websocket.closed?
      @websocket
    end

    def close
      @keep_alive_task&.stop
      @read_task&.stop
      @websocket&.close
    end

    def for_sha256(sha256)
      Async do |task|
        task.with_timeout(@timeout) do
          verdict_notification = Async::Notification.new
          guid = SecureRandom.uuid.to_s
          websocket = get_authenticated_websocket
          verdict_request =  JSON.generate({:kind => "VerdictRequest",
                                            :session_id => @session_id,
                                            :sha256 => sha256,
                                            :guid => guid})
          @requests[guid] = verdict_notification
          websocket.write(verdict_request)
          websocket.flush
          VaasVerdict.new(verdict_notification.wait)
        rescue Async::TimeoutError
          close
          raise VaasTimeoutError
        end
      end
    end

    def for_url(url)
      Async do |task|
        task.with_timeout(@timeout) do
          verdict_notification = Async::Notification.new
          guid = SecureRandom.uuid.to_s
          websocket = get_authenticated_websocket
          verdict_request =  JSON.generate({:kind => "VerdictRequestForUrl",
                                            :session_id => @session_id,
                                            :url => url,
                                            :guid => guid})
          @requests[guid] = verdict_notification
          websocket.write(verdict_request)
          websocket.flush
          VaasVerdict.new(verdict_notification.wait)
        rescue Async::TimeoutError
          close
          raise VaasTimeoutError
        end
      end
    end

    def for_file(path)
      Async do |task|
        task.with_timeout(@timeout) do
          sha256 = Digest::SHA256.file(path).hexdigest
          verdict_notification = Async::Notification.new
          guid = SecureRandom.uuid.to_s
          websocket = get_authenticated_websocket
          verdict_request =  JSON.generate({:kind => "VerdictRequest",
                                            :session_id => @session_id,
                                            :sha256 => sha256,
                                            :guid => guid})
          @requests[guid] = verdict_notification
          websocket.write(verdict_request)
          websocket.flush
          message = verdict_notification.wait

          if message['verdict'] == "Unknown"
            upload_notification = Async::Notification.new
            @requests[guid] = upload_notification
            upload(message, path)
            VaasVerdict.new(upload_notification.wait)
          else
            VaasVerdict.new(message)
          end
        rescue Async::TimeoutError
          close
          raise VaasTimeoutError
        end
      end
    end

    def upload(message, path)
      Async do |task|
        task.with_timeout(@timeout) do
          token = message['upload_token']
          url = message['url']
          endpoint = Async::HTTP::Endpoint.parse(url)
          client = Async::HTTP::Client.new(endpoint, protocol: Async::HTTP::Protocol::HTTP1)

          header = [['authorization', token]]
          body = Protocol::HTTP::Body::File.open(File.join(path))

          response = client.put(url, header, body)
          response.read

          raise VaasUploadError, "Upload failed with code: #{response.status}" if response.status != 200
        rescue Async::TimeoutError
          close
          raise VaasTimeoutError, "Upload timed out"
        ensure
          client&.close
        end
      end
    end
  end
end
