module OoAuth
  class Credentials
    AUTH_ATTRIBUTES = [:consumer_key, :consumer_secret, :token, :token_secret] 
  
    attr_reader *AUTH_ATTRIBUTES
    
    class << self
      def generate
        new(*4.times.collect { OoAuth.generate_key })
      end
    end

    def initialize(consumer_key, consumer_secret, token, token_secret)
      @consumer_key, @consumer_secret, @token, @token_secret = consumer_key, consumer_secret, token, token_secret
    end
    
    def attributes
      AUTH_ATTRIBUTES.inject({}) { |hsh, attr| hsh.update(attr => send(attr)) }
    end
    
  end
end