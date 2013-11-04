require 'oo_auth/configuration_error'
require 'oo_auth/nonce'
require 'oo_auth/nonce/abstract_store'
require 'oo_auth/authorization'

module OoAuth
  # Initialize with instance of store
  # OoAuth.nonce_store = OoAuth::Nonce::RedisStore.new(namespace: 'foo')
  mattr_accessor :nonce_store
  
  # Define a lookup method for access token verification
  # It should be callable (proc) or respond to +authorization+ method,
  # with the argument being the consumer key.
  # The proc or method call should return an instance of
  # OoAuth::Authorization if the consumer key exists, or nil.
  mattr_accessor :authorizer
  
  # request tokens are passed between the consumer and the provider out of
  # band (i.e. callbacks cannot be used), per section 6.1.1
  OUT_OF_BAND = 'oob'

  # required parameters, per sections 6.1.1, 6.3.1, and 7
  PARAMETERS = %w(callback consumer_key token signature_method timestamp nonce verifier version signature body_hash)

  # reserved character regexp, per section 5.1
  RESERVED_CHARACTERS = /[^a-zA-Z0-9\-\.\_\~]/
  
  # OoAuth only supports HMAC-SHA1
  SIGNATURE_METHOD = 'HMAC-SHA1'
  
  class << self
  
    # Generate a random key of up to +size+ bytes. The value returned is Base64 encoded with non-word
    # characters removed.
    def generate_key(size = 32)
      Base64.encode64(OpenSSL::Random.random_bytes(size)).gsub(/\W/, '')
    end

    alias_method :generate_nonce, :generate_key
    
    def authorization(consumer_key)
      if authorizer.respond_to?(:call)
        authorizer.call(consumer_key)
      elsif authorizer.respond_to?(:authorization)
        authorizer.authorization(consumer_key)
      else
        fail ConfigurationError, 'authorizer not callable'
      end
    end
  end
  
end