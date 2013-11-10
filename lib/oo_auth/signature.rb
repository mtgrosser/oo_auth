module OoAuth
  module Signature

    class << self
      def hmac_sha1_signature(base_string, consumer_secret, token_secret)
        Base64.strict_encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, OoAuth.encode(consumer_secret, token_secret), base_string))
      end

      def calculate_signature(proxy, credentials, params)
        hmac_sha1_signature(proxy.signature_base_string(params), credentials.consumer_secret, credentials.token_secret)
      end

      def sign!(proxy, credentials)
        params = {
          oauth_version: '1.0',
          oauth_nonce: OoAuth.generate_nonce,
          oauth_timestamp: OoAuth.timestamp,
          oauth_signature_method: SIGNATURE_METHOD,
          oauth_consumer_key: credentials.consumer_key,
          oauth_token: credentials.token
        }
      
        params[:oauth_signature] = calculate_signature(proxy, credentials, params)

        proxy.authorization = authorization_header(params)
      end
      
      # Check signature validity without remembering nonce - DO NOT use to authorize actual requests
      def valid?(proxy, credentials)
        verify_timestamp!(proxy) &&
        calculate_signature(proxy, credentials, proxy.oauth_params_without_signature) == proxy.signature
      end
      
      # Verify signature and remember nonce - use this to authorize actual requests
      def verify!(proxy, credentials)
        !!(valid?(proxy, credentials) && remember_nonce!(proxy))
      end
      
      private
      
      def verify_timestamp!(proxy)
        (OoAuth.timestamp - proxy.timestamp.to_i).abs < MAX_TIMESTAMP_DEVIATION
      end

      def remember_nonce!(proxy)
        Nonce.remember(proxy.nonce, proxy.timestamp)
      end
      
      def authorization_header(params)
        'OAuth ' + params.map { |k, v| "#{OoAuth.escape(k)}=\"#{OoAuth.escape(v)}\"" }.join(', ')
      end
      
    end
  end
end