module OoAuth
  
  # request tokens are passed between the consumer and the provider out of
  # band (i.e. callbacks cannot be used), per section 6.1.1
  OUT_OF_BAND = 'oob'

  # FIXME: ordering
  # required parameters, per sections 6.1.1, 6.3.1, and 7
  PARAMETERS = %w(oauth_callback oauth_consumer_key oauth_token oauth_signature_method oauth_timestamp oauth_nonce oauth_verifier oauth_version oauth_signature oauth_body_hash)

  # reserved character regexp, per section 5.1
  RESERVED_CHARACTERS = /[^a-zA-Z0-9\-\.\_\~]/
  
  # OoAuth only supports HMAC-SHA1
  SIGNATURE_METHOD = 'HMAC-SHA1'
  
  MAX_TIMESTAMP_DEVIATION = 5 * 60
  
end