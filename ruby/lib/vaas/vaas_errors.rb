module VAAS
# Authentication Error
class VaasAuthenticationError < StandardError
  def initialize(msg = "authentication failed")
    super
  end
end

# Generic Timeout Error
class VaasTimeoutError < StandardError
  def initialize(msg = "connection has timed out")
    super
  end
end

# Invalid State
class VaasInvalidStateError < StandardError
  def initialize(msg = "connect() was not called")
    super
  end
end

# Connection closed
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
