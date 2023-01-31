require 'minitest/autorun'
require 'minitest/spec'
require 'async'

require_relative '../lib/vaas/client_credentials_grant_authenticator'
require_relative '../lib/vaas/vaas_main'

# # test locally with .env file (comment this when push)
# require 'dotenv'
# Dotenv.load
# CLIENT_ID = ENV['CLIENT_ID']
# CLIENT_SECRET = ENV['CLIENT_SECRET']
# TOKEN_URL = ENV['TOKEN_URL']
# VAAS_URL = ENV['VAAS_URL']

# automatic test (need this when push)
CLIENT_ID = ENV.fetch('CLIENT_ID')
CLIENT_SECRET = ENV.fetch('CLIENT_SECRET')
TOKEN_URL = ENV.fetch('TOKEN_URL')
VAAS_URL = ENV.fetch('VAAS_URL')

class VaasTest < Minitest::Test
  TEST_CLASS = self
  describe TEST_CLASS do
    def create(token = nil, timeout = nil)
      authenticator = VAAS::ClientCredentialsGrantAuthenticator.new(
        CLIENT_ID,
        CLIENT_SECRET,
        TOKEN_URL
      )
      token = token || authenticator.get_token
      timeout = timeout || 600
      vaas = VAAS::VaasMain.new(VAAS_URL, timeout)

      return [vaas, token]
    end

    describe 'succeeds' do

      specify 'for_sha356' do
        vaas, token = create
        Async do
          vaas.connect(token)

          result = vaas.for_sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
          verdict = result.wait.verdict
          assert_equal "Malicious", verdict

          vaas.close
        end
      end

      specify 'for_file' do
        vaas, token = create
        Async do
          vaas.connect(token)

          random_text = (0...8).map { (65 + rand(26)).chr }.join
          File.open("test.txt", "w") { |f| f.write(random_text) }
          result = vaas.for_file("./test.txt")
          verdict = result.wait.verdict
          assert_equal "Clean", verdict

          vaas.close
        end
      end

      specify 'for_url' do
        vaas, token = create
        Async do
          vaas.connect(token)

          result = vaas.for_url("https://secure.eicar.org/eicar.com.txt")
          verdict = result.wait.verdict
          assert_equal "Malicious", verdict

          vaas.close
        end
      end

      specify 'pup' do
        vaas, token = create
        Async do
          vaas.connect(token)

          result = vaas.for_sha256("d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad")
          verdict = result.wait.verdict
          assert_equal "Pup", verdict

          vaas.close
        end
      end

      # # Tested locally with 1.5 GB File
      # specify 'for_big_file' do
      #   vaas, token = create
      #   Async do
      #     vaas.connect(token)
      #
      #     result = vaas.for_file("BIG_FILE")
      #     verdict = result.wait.verdict
      #     assert_equal "Clean", verdict
      #
      #     vaas.close
      #   end
      # end
    end

    describe 'fail' do

      specify 'not_connected' do
        vaas = VAAS::VaasMain.new
        assert_raises VAAS::VaasInvalidStateError do
          vaas.for_sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f").wait
        end
      end

      specify 'not_authenticated' do
        vaas, token = create("invalid token", 600)
        Async do
          assert_raises VAAS::VaasAuthenticationError do
            vaas.connect(token)
          end
          vaas.close
        end
      end

      specify 'connection_closed' do
        vaas, token = create
        Async do
          vaas.connect(token)
          vaas.close
          assert_raises VAAS::VaasConnectionClosedError do
            vaas.for_sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f").wait
          end
        end
      end

      specify 'timeout' do
        vaas, token = create(nil, 0.001)
        Async do
          random_text = (0...8).map { (65 + rand(26)).chr }.join
          File.open("test.txt", "w") { |f| f.write(random_text) }

          assert_raises VAAS::VaasTimeoutError do
            vaas.connect(token)
            vaas.for_file("./test.txt").wait
          end
        ensure
          vaas.close
        end
      end
    end
  end
end
