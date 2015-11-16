module OoAuth
  # request tokens are passed between the consumer and the provider out of
  # band (i.e. callbacks cannot be used), per section 6.1.1
  OUT_OF_BAND = 'oob'

  # FIXME: ordering
  # required parameters, per sections 6.1.1, 6.3.1, and 7
  PARAMETERS = %w(oauth_callback oauth_consumer_key oauth_token oauth_signature_method oauth_timestamp oauth_nonce oauth_verifier oauth_version oauth_signature oauth_body_hash)

  # reserved character regexp, per section 5.1
  RESERVED_CHARACTERS = /[^a-zA-Z0-9\-\.\_\~]/
  
  # Supported signature methods
  HMAC_SHA1 = 'HMAC-SHA1'
  HMAC_SHA256 = 'HMAC-SHA256'
  HMAC_SHA512 = 'HMAC-SHA512'
  
  SUPPORTED_SIGNATURE_METHODS = { HMAC_SHA1   => OpenSSL::Digest::SHA1,
                                  HMAC_SHA256 => OpenSSL::Digest::SHA256,
                                  HMAC_SHA512 => OpenSSL::Digest::SHA512 }
  
  DEFAULT_SIGNATURE_METHOD = HMAC_SHA1
  
  MAX_TIMESTAMP_DEVIATION = 5 * 60
end
