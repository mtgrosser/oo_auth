module OoAuth
  class Nonce
    MAX_LENGTH = 255
    
    attr_reader :value, :timestamp, :errors
    
    class << self
      def store
        OoAuth.nonce_store || fail(ConfigurationError, 'no nonce store set')
      end

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
      @errors << 'nonce value cannot be blank' if value.blank?
      @errors << 'nonce value too big' if value.size > MAX_LENGTH
      @errors << 'illegal nonce timestamp' if timestamp <= 0
      @errors.empty?
    end
    
    def save
      !!(valid? && self.class.store.create(self))
    end
    
  end
end