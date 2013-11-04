module OoAuth
  class Authorization
    ATTRIBUTES = [:consumer_key, :consumer_secret, :token, :token_secret] 
  
    attr_reader *ATTRIBUTES

    class << self

      def generate
        new(*4.times.collect { OoAuth.generate_key })
      end

      # Parse an Authorization / WWW-Authenticate header into a hash. Takes care of unescaping and
      # removing surrounding quotes. Raises a OAuth::Problem if the header is not parsable into a
      # valid hash. Does not validate the keys or values.
      #
      #   hash = parse(headers['Authorization'] || headers['WWW-Authenticate'])
      #   hash['oauth_timestamp']
      #     #=>"1234567890"
      #
      def parse(header)
        # decompose
        params = header[6, header.length].split(/[,=&]/)

        # odd number of arguments - must be a malformed header.
        raise "Invalid authorization header" if params.size % 2 != 0

        params.map! do |v|
          # strip and unescape
          val = unescape(v.strip)
          # strip quotes
          val.sub(/^\"(.*)\"$/, '\1')
        end

        # convert into a Hash and remove non-OAuth parameters
        Hash[*params.flatten].reject { |k,v| !PARAMETERS.include?(k) }
      end

      # Escape +value+ by URL encoding all non-reserved character.
      #
      # See Also: {OAuth core spec version 1.0, section 5.1}[http://oauth.net/core/1.0#rfc.section.5.1]
      def escape(value)
        URI.escape(value.to_s, OAuth::RESERVED_CHARACTERS)
      rescue ArgumentError
        URI.escape(value.to_s.force_encoding(Encoding::UTF_8), OAuth::RESERVED_CHARACTERS)
      end

      def unescape(value)
        URI.unescape(value.gsub('+', '%2B'))
      end

      # cf. http://tools.ietf.org/html/rfc5849#section-3.4.1.1
      # cf. http://tools.ietf.org/html/rfc5849#section-3.4.4
      def encode(*components)
        components.map { |component| escape(component) }.join('&')
      end

      def hmac_sha1_signature(base_string, consumer_secret, token_secret)
        Base64.strict_encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, encode(consumer_secret, token_secret), base_string))
      end
    end

    def initialize(consumer_key, consumer_secret, token, token_secret)
      @consumer_key, @consumer_secret, @token, @token_secret = consumer_key, consumer_secret, token, token_secret
      
      ATTRIBUTES.each do |attr|
        fail ArgumentError, "#{attr} cannot be blank" if send(attr).blank?
      end
    end
    
    def attributes
      ATTRIBUTES.hmap { |attr| send(attr) }
    end

    def sign!(http, request, options = {})
      params = {
        oauth_version: '1.0',
        oauth_nonce: OoAuth.generate_nonce,
        oauth_timestamp: Time.now.utc.to_i,
        oauth_signature_method: SIGNATURE_METHOD,
        oauth_consumer_key: consumer_key,
        oauth_token: token
      }

      params[:oauth_signature] = 
        self.class.hmac_sha1_signature(signature_base_string(http, request, params),
                                       consumer_secret,
                                       token_secret)

      request['Authorization'] = authorization_header(params)
    end

    def valid?(http, response, options = {})
      return false
      consumer_secret = options.fetch(:consumer_secret)
      signature_method = options.fetch(:signature_method) { 'HMAC-SHA1' }
      token_secret = options[:token_secret]
      params = parse(response.headers['Authorization'])
    end

    private

    def signature_base_string(http, request, params = {})
      encoded_params = params_encode(params_array(request) + params_array(params))
      self.class.encode(request.method, normalized_request_uri(http, request), encoded_params)
    end

    # FIXME: cf nested params implementation in oauth gem
    def params_array(object)
      case object
      when Array then return object
      when Hash then return object.to_a
      when Net::HTTPRequest
        tmp = object.path.split('?')
        tmp[1] ? params_decode(tmp[1]) : []
      else
        raise "error: cannot convert #{object.class} object to params array"
      end
    end

    def params_decode(string)
      string.split('&').each_with_object([]) do |param, array|
        k, v = *param.split('=')
        array << [self.class.unescape(k), v && self.class.unescape(v)]
      end
    end

    # cf. http://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
    def params_encode(params)
      params.map { |k, v| [self.class.escape(k), self.class.escape(v)] }.sort.map { |k, v| "#{k}=#{v}" }.join('&')
    end

    def normalized_request_uri(http, request)
      if http.port == Net::HTTP.default_port
        scheme, port = :http, nil
      elsif http.port == Net::HTTP.https_default_port
        scheme, port = :https, nil
      elsif http.use_ssl?
        scheme, port = :https, http.port
      else
        scheme, port = :http, http.port
      end

      uri = "#{scheme}://#{http.address.downcase}"
      uri += ":#{port}" if port
      uri += request.path.split('?').first
      uri
    end

    def authorization_header(params)
      'OAuth ' + params.map { |k, v| "#{self.class.escape(k)}=\"#{self.class.escape(v)}\"" }.join(', ')
    end
    
  end
end