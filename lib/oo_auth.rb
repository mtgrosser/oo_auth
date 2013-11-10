require 'openssl'
require 'uri'
require 'net/http'
require 'base64'

require 'oo_auth/version'
require 'oo_auth/constants'
require 'oo_auth/configuration_error'
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
    # It should be callable (proc) or respond to +authorizer+ method,
    # with the argument being the consumer key.
    # The proc or method call should return
    # - if the consumer key exists:
    #   an object which responding to +authorization+ with an instance of 
    #   OoAuth::Authorization
    # - nil if the consumer key is unknown.
    attr_accessor :authorization_store
    
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
      URI.escape(value.to_s, RESERVED_CHARACTERS)
    rescue ArgumentError
      URI.escape(value.to_s.force_encoding(Encoding::UTF_8), RESERVED_CHARACTERS)
    end

    def unescape(value)
      URI.unescape(value.gsub('+', '%2B'))
    end
    
    # cf. http://tools.ietf.org/html/rfc5849#section-3.4.1.1
    # cf. http://tools.ietf.org/html/rfc5849#section-3.4.4
    def encode(*components)
      components.map { |component| OoAuth.escape(component) }.join('&')
    end
    
    def timestamp
      Time.now.utc.to_i
    end
    
    def authorization(consumer_key, token)
      return if consumer_key.blank?
      if authorization_store.respond_to?(:call)
        authorization_store.call(consumer_key, token)
      elsif authorization_store.respond_to?(:authorization)
        authorization_store.authorization(consumer_key, token)
      else
        fail ConfigurationError, 'authorization store not callable'
      end
    end
    
    def authenticate!(*args)
      proxy = RequestProxy.new(*args)
      return unless authorization = self.authorization(proxy.consumer_key, proxy.token)
      return unless Signature.verify!(proxy, credentials)
      authorization
    end
    
  end
  
end