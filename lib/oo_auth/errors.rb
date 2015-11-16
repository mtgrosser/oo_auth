module OoAuth
  class Error < StandardError; end
  class ConfigurationError < Error; end
  class UnsupportedSignatureMethod < Error; end
end