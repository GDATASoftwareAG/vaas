module VAAS
class VaasVerdict

  attr_reader :sha256, :verdict, :guid

  def initialize(response)
    @sha256 = response['sha256']
    @verdict = response['verdict']
    @guid = response['guid']
  end

end
end
