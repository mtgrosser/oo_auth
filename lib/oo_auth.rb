require 'openssl'
require 'uri'
require 'net/http'
require 'base64'

require 'oo_auth/version'
require 'oo_auth/constants'
require 'oo_auth/errors'
require 'oo_auth/nonce'
require 'oo_auth/nonce/abstract_store'
require 'oo_auth/request_proxy'
require 'oo_auth/credentials'
require 'oo_auth/signature'

module OoAuth
  
  class << self
    # Initialize with instance of store
    # OoAuth.nonce_store = OoAuth::Nonce::RedisStore.new(namespace: 'foo')
    attr_accessor :nonce_store
  
    # Define a lookup method for access token verification
    # It should be callable (proc) or provide an +authorization+ method,
    # with the argument being the consumer key and token.
    # The proc or method call should return
    # - if the consumer key/token combination exists:
    #   an object which responding to +credentials+ with an 
    #   initialized instance of 
    #   OoAuth::Credentials
    # - nil otherwise.
    attr_accessor :authorization_store
    
    def signature_methods
      @signature_methods ||= SUPPORTED_SIGNATURE_METHODS
    end
    
    # Set the available signature methods
    # You can either use strings or symbols, e.g.
    # ['HMAC_SHA1', :hmac_sha256]
    def signature_methods=(methods)
      @signature_methods = methods.collect do |method|
        method = method.to_s.upcase.sub('_', '-')
        raise UnsupportedSignatureMethod, method.inspect unless SUPPORTED_SIGNATURE_METHODS.include?(method)
        method
      end
    end
    
    # Check if the signature method is valid, raise error if not
    #
    # Supported values:
    # - 'HMAC-SHA1'
    # - 'HMAC-SHA256'
    # - 'HMAC-SHA512'
    #
    def verify_signature_method!(value)
      raise UnsupportedSignatureMethod, value.inspect unless signature_methods.include?(value)
    end
    
    def signature_method
      @signature_method ||= DEFAULT_SIGNATURE_METHOD
    end

    # Set the signature method to use
    def signature_method=(value)
      verify_signature_method!(value)
      @signature_method = value
    end
    
    # Generate a random key of up to +size+ bytes. The value returned is Base64 encoded with non-word
    # characters removed.
    def generate_key(size = 32)
      Base64.encode64(OpenSSL::Random.random_bytes(size)).gsub(/\W/, '')
    end

    alias_method :generate_nonce, :generate_key
    
    # Escape +value+ by URL encoding all non-reserved character.
    #
    # See Also: {OAuth core spec version 1.0, section 5.1}[http://oauth.net/core/1.0#rfc.section.5.1]
    def escape(value)
      uri_escape(value.to_s)
    rescue ArgumentError
      uri_escape(value.to_s.force_encoding(Encoding::UTF_8))
    end

    def unescape(value)
      URI.decode_www_form_component(value.gsub('+', '%2B'))
    end
    
    # cf. http://tools.ietf.org/html/rfc5849#section-3.4.1.1
    # cf. http://tools.ietf.org/html/rfc5849#section-3.4.4
    def encode(*components)
      components.map { |component| OoAuth.escape(component) }.join('&')
    end
    
    # Current UTC timestamp
    def timestamp
      Time.now.utc.to_i
    end
    
    def authorization(consumer_key, token)
      if authorization_store.respond_to?(:call)
        authorization_store.call(consumer_key, token)
      elsif authorization_store.respond_to?(:authorization)
        authorization_store.authorization(consumer_key, token)
      else
        fail ConfigurationError, 'authorization store not callable'
      end
    end
    
    # Use this to sign Net::HTTP or ActionDispatch requests
    def sign!(*args)
      credentials = args.pop
      proxy = RequestProxy.new(*args)
      Signature.sign!(proxy, credentials)
    end
    
    # Use this in your controllers to verify the OAuth signature
    # of a request.
    def authorize!(*args)
      proxy = RequestProxy.new(*args)
      return unless authorization = self.authorization(proxy.consumer_key, proxy.token)
      return unless Signature.verify!(proxy, authorization.credentials)
      authorization
    end
    
    private
    
    def uri_escape(string)
      encoding = string.encoding
      string.b.gsub(RESERVED_CHARACTERS) { |m|
        '%' + m.unpack('H2' * m.bytesize).join('%').upcase }.force_encoding(encoding)
    end
    
  end
  
end
