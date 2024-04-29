module VAAS
  class VaasVerdict

    attr_reader :sha256, :verdict, :guid, :detection, :mime_type, :file_type

    def initialize(response)
      @sha256 = response['sha256']
      @verdict = response['verdict']
      @guid = response['guid']
      @detection = response.fetch("detection", "")
      @mime_type = response.fetch("mime_type", "")
      @file_type = response.fetch("file_type", "")
    end

  end
end
