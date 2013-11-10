module OoAuth
  class Nonce
    MAX_LENGTH = 255
    
    attr_reader :value, :timestamp, :errors
    
    class << self
      def remember(value, timestamp)
        new(value, timestamp).save
      end
            
      def generate
        new(OoAuth.generate_nonce, Time.now.utc.to_i)
      end
    end
    
    def initialize(value, timestamp)
      @value, @timestamp = value, timestamp.to_i
    end
    
    def valid?
      @errors = []
      @errors << 'nonce value cannot be blank' if value.to_s == ''
      @errors << 'nonce value too big' if value.size > MAX_LENGTH
      @errors << 'illegal nonce timestamp' if timestamp <= 0
      @errors.empty?
    end
    
    def save
      return false unless valid?
      if store.respond_to?(:call)
        store.call(self)
      elsif store.respond_to?(:remember)
        store.remember(self)
      else
        fail ConfigurationError, 'nonce store not callable'
      end
    end

    end

    private
    
    def store
      OoAuth.nonce_store || fail(ConfigurationError, 'no nonce store set')
    end
    
  end
end