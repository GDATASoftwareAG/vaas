require 'minitest/autorun'
require 'minitest/spec'
require 'dotenv'
require 'async'

require_relative '../lib/client_credentials_grant_authenticator'
require_relative '../lib/vaas'

Dotenv.load
CLIENT_ID = ENV["CLIENT_ID"]
CLIENT_SECRET = ENV["CLIENT_SECRET"]
TOKEN_URL = ENV["TOKEN_URL"]
VAAS_URL = ENV["VAAS_URL"]

class VaasTest < Minitest::Test
  TOOL_CLASS = self
  describe TOOL_CLASS do


  def create(token=nil)
    authenticator = ClientCredentialsGrantAuthenticator.new(
      CLIENT_ID,
      CLIENT_SECRET,
      TOKEN_URL
    )
    vaas = Vaas.new(VAAS_URL)
    token = token || authenticator.get_token

    return [vaas, token]
  end

  describe 'succeeds' do

    specify 'for_sha356' do
      vaas, token = create
      Async do
        Async { vaas.connect(token) }.wait

        result = vaas.for_sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        verdict = result.verdict
        assert_equal "Malicious", verdict
      ensure
        Async { vaas.close }
      end
    end

    specify 'for_file' do
      vaas, token = create
      Async do
        Async { vaas.connect(token) }.wait

        result = vaas.for_file("./test.txt")
        verdict = result.verdict
        assert_equal "Clean", verdict
      ensure
        Async { vaas.close }
      end
    end

    specify 'for_url' do
      vaas, token = create
      Async do
        Async { vaas.connect(token) }.wait

        result = vaas.for_url("https://secure.eicar.org/eicar.com.txt")
        verdict = result.verdict
        assert_equal verdict, "Malicious"
      ensure
        Async { vaas.close }
      end
    end

    specify 'pup' do
      vaas, token = create
      Async do
        Async { vaas.connect(token) }.wait

        result = vaas.for_sha256("d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad")
        verdict = result.verdict
        assert_equal verdict, "Pup"
      ensure
        Async { vaas.close }
      end
    end
  end

  describe 'fail' do

    specify 'not_connected' do
      vaas = Vaas.new
      assert_raises VaasInvalidStateError do
        vaas.for_sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
      end
    end

    specify 'not_authenticated' do
      vaas, token = create("invalid token")
      Async do
        assert_raises VaasAuthenticationError do
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
        assert_raises VaasConnectionClosedError do
          result vaas.for_sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        end
      end
    end

  end
  end
  end
