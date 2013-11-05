module OoAuth
  class Authorization
    AUTH_ATTRIBUTES = [:consumer_key, :consumer_secret, :token, :token_secret] 
  
    attr_reader *AUTH_ATTRIBUTES
    
    class << self

      def generate
        new(*4.times.collect { OoAuth.generate_key })
      end

      def hmac_sha1_signature(base_string, consumer_secret, token_secret)
        Base64.strict_encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, OoAuth.encode(consumer_secret, token_secret), base_string))
      end
    end

    def initialize(consumer_key, consumer_secret, token, token_secret, source = nil)
      @consumer_key, @consumer_secret, @token, @token_secret = consumer_key, consumer_secret, token, token_secret
      
      AUTH_ATTRIBUTES.each do |attr|
        fail ArgumentError, "#{attr} cannot be blank" if send(attr).blank?
      end
    end
    
    def attributes
      AUTH_ATTRIBUTES.hmap { |attr| send(attr) }
    end
    
    def calculate_signature(proxy, params)
      self.class.hmac_sha1_signature(proxy.signature_base_string(params), consumer_secret, token_secret)
    end

    def sign!(proxy)
      params = {
        oauth_version: '1.0',
        oauth_nonce: OoAuth.generate_nonce,
        oauth_timestamp: OoAuth.timestamp,
        oauth_signature_method: SIGNATURE_METHOD,
        oauth_consumer_key: consumer_key,
        oauth_token: token
      }
      
      params[:oauth_signature] = calculate_signature(proxy, params)

      proxy.headers['Authorization'] = authorization_header(params)
    end      
    
    # This method is unaccessible as long 
    def source
      return unless @validated
      @source
    end

    def authorization_header(params)
      'OAuth ' + params.map { |k, v| "#{OoAuth.escape(k)}=\"#{OoAuth.escape(v)}\"" }.join(', ')
    end
    
  end
end