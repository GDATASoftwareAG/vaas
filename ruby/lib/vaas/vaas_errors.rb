module VAAS
  class VaasAuthenticationError < StandardError
    def initialize(msg = "authentication failed")
      super
    end
  end

  class VaasTimeoutError < StandardError
    def initialize(msg = "connection has timed out")
      super
    end
  end

  class VaasInvalidStateError < StandardError
    def initialize(msg = "connect() was not called")
      super
    end
  end

  class VaasConnectionClosedError < StandardError
    def initialize(msg = "connection closed")
      super
    end
  end

  class VaasUploadError < StandardError
    def initialize(msg = "upload failed")
      super
    end
  end
end
