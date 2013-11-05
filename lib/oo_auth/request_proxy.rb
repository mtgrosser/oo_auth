module OoAuth
  class RequestProxy

    attr_reader :port, :ssl, :host, :path, :headers, :method

    class << self
      
      
      # Parse an Authorization / WWW-Authenticate header into a hash. Takes care of unescaping and
      # removing surrounding quotes. Raises a OAuth::Problem if the header is not parsable into a
      # valid hash. Does not validate the keys or values.
      #
      #   hash = parse(headers['Authorization'] || headers['WWW-Authenticate'])
      #   hash['oauth_timestamp']
      #     #=>"1234567890"
      #
      def parse(header)
        header = header.to_s
        return unless header.starts_with?('OAuth ')
        # decompose
        params = header[6, header.length].split(',').inject({}) do |hsh, str|
          key, value = str.split('=').map { |s| OoAuth.unescape(s.strip) }
          if PARAMETERS.include?(key)
            hsh[key] = value.sub(/^\"(.*)\"$/, '\1')
          end
          hsh
        end
      end
    end
  
    def initialize(*args)
      case args.size
      when 1 # ActionDispatch request
        request = args[0]
        @port = request.port
        @ssl = request.ssl?
        @path = request.fullpath
        @host = request.host
        @headers = request.headers
      when 2 # Net:HTTP request
        http, request = args[0], args[1]
        @port = http.port
        @ssl = http.use_ssl?
        @path = request.path
        @host = http.address
        @headers = request
      else
        raise ArgumentError, 'wrong number of arguments'
      end
      @method = request.method
    end
    
    def valid?(authorization)
      authorization.calculate_signature(self, oauth_params.except('oauth_signature')) == self.signature and
      valid_timestamp? and
      remember_nonce!
    end
    
    def valid_timestamp?
      (OoAuth.timestamp - timestamp.to_i).abs < MAX_TIMESTAMP_DEVIATION
    end
    
    def remember_nonce!
      Nonce.remember(nonce, timestamp)
    end
    
    def normalized_request_uri
      if self.port == Net::HTTP.default_port
        scheme, port = :http, nil
      elsif self.port == Net::HTTP.https_default_port
        scheme, port = :https, nil
      elsif ssl
        scheme, port = :https, self.port
      else
        scheme, port = :http, self.port
      end

      uri = "#{scheme}://#{host.downcase}"
      uri += ":#{port}" if port
      uri += path.split('?').first
      uri
    end
    
    def oauth_params
      self.class.parse(headers['Authorization'])
    end
    
    PARAMETERS.each do |parameter|
      define_method "#{parameter[6..-1]}" do
        oauth_params[parameter]
      end
    end
    
    def signature_base_string(params = {})
      encoded_params = params_encode(params_array(self) + params_array(params))
      OoAuth.encode(method, normalized_request_uri, encoded_params)
    end

    # FIXME: cf nested params implementation in oauth gem
    def params_array(object)
      case object
      when Array then return object
      when Hash then return object.to_a
      when RequestProxy
        tmp = object.path.split('?')
        tmp[1] ? params_decode(tmp[1]) : []
      else
        raise "error: cannot convert #{object.class} object to params array"
      end
    end

    def params_decode(string)
      string.split('&').each_with_object([]) do |param, array|
        k, v = *param.split('=')
        array << [OoAuth.unescape(k), v && OoAuth.unescape(v)]
      end
    end

    # cf. http://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
    def params_encode(params)
      params.map { |k, v| [OoAuth.escape(k), OoAuth.escape(v)] }.sort.map { |k, v| "#{k}=#{v}" }.join('&')
    end

  end
end