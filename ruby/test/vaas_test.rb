require 'minitest/autorun'
require 'minitest/spec'
require 'async'

require_relative '../lib/vaas/client_credentials_grant_authenticator'
require_relative '../lib/vaas/vaas_main'

CLIENT_ID = ENV.fetch('CLIENT_ID')
CLIENT_SECRET = ENV.fetch('CLIENT_SECRET')
TOKEN_URL = ENV.fetch('TOKEN_URL')
VAAS_URL = ENV.fetch('VAAS_URL')

# # for manuel testing with .env file:
# require 'dotenv'
# Dotenv.load
# CLIENT_ID = ENV['CLIENT_ID']
# CLIENT_SECRET = ENV['CLIENT_SECRET']
# TOKEN_URL = ENV['TOKEN_URL']
# VAAS_URL = ENV['VAAS_URL']

class VaasTest < Minitest::Test
  TEST_CLASS = self
  describe TEST_CLASS do
    def create(token=nil)
      authenticator = VAAS::ClientCredentialsGrantAuthenticator.new(
        CLIENT_ID,
        CLIENT_SECRET,
        TOKEN_URL
      )
      vaas = VAAS::VaasMain.new(VAAS_URL)
      token = token || authenticator.get_token

      return [vaas, token]
    end

    describe 'succeeds_single_requests' do

      specify 'for_sha356' do
        vaas, token = create
        Async do
          Async { vaas.connect(token) }.wait

          verdict = vaas.for_sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
          assert_equal "Malicious", verdict[0].verdict
        ensure
          Async { vaas.close }
        end
      end

      specify 'for_file' do
        vaas, token = create
        Async do
          Async { vaas.connect(token) }.wait

          random_text = (0...8).map { (65 + rand(26)).chr }.join
          File.open("test.txt", "w") {|f| f.write(random_text) }

          verdict = vaas.for_file("./test.txt")
          assert_equal "Clean", verdict[0].verdict
        ensure
          Async { vaas.close }
        end
      end

      specify 'for_url' do
        vaas, token = create
        Async do
          Async { vaas.connect(token) }.wait

          verdict = vaas.for_url("https://secure.eicar.org/eicar.com.txt")
          assert_equal "Malicious", verdict[0].verdict
        ensure
          Async { vaas.close }
        end
      end

      specify 'pup' do
        vaas, token = create
        Async do
          Async { vaas.connect(token) }.wait

          verdict = vaas.for_sha256("d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad")
          assert_equal "Pup", verdict[0].verdict
        ensure
          Async { vaas.close }
        end
      end
    end

    describe 'succeeds_list_requests' do

      specify 'for_sha356' do
        vaas, token = create
        Async do
          Async { vaas.connect(token) }.wait
          sha256_list =["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"]
          verdict = vaas.for_sha256(sha256_list)
          assert_equal "Malicious", verdict[0].verdict
          assert_equal "Malicious", verdict[1].verdict
        ensure
          Async { vaas.close }
        end
      end

      specify 'for_file' do
        vaas, token = create
        Async do
          Async { vaas.connect(token) }.wait

          random_text = (0...8).map { (65 + rand(26)).chr }.join
          File.open("test.txt", "w") {|f| f.write(random_text) }
          random_text = (0...8).map { (65 + rand(26)).chr }.join
          File.open("test2.txt", "w") {|f| f.write(random_text) }

          verdict = vaas.for_file(["./test.txt", "./test2.txt"])
          assert_equal "Clean", verdict[0].verdict
          assert_equal "Clean", verdict[1].verdict
        ensure
          Async { vaas.close }
        end
      end

      specify 'for_url' do
        vaas, token = create
        Async do
          Async { vaas.connect(token) }.wait

          verdict = vaas.for_url(["https://secure.eicar.org/eicar.com.txt", "https://www.gdata.de/"])
          assert_equal "Malicious", verdict[0].verdict
          assert_equal "Clean", verdict[1].verdict
        ensure
          Async { vaas.close }
        end
      end
    end

    describe 'fail' do

      specify 'not_connected' do
        vaas = VAAS::VaasMain.new
        assert_raises VAAS::VaasInvalidStateError do
          vaas.for_sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        end
      end

      specify 'not_authenticated' do
        vaas, token = create("invalid token")
        Async do
          assert_raises VAAS::VaasAuthenticationError do
            vaas.connect(token)
          end
        ensure
          Async { vaas.close }
        end
      end

      specify 'connection_closed' do
        vaas, token = create
        Async do
          Async { vaas.connect(token) }.wait
          Async {vaas.close}
          assert_raises VAAS::VaasConnectionClosedError do
            vaas.for_sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
          end
        end
      end
    end
  end
end
