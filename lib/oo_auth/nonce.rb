module OoAuth
  class Nonce
    MAX_LENGTH = 255
    
    attr_reader :value, :timestamp
    
    class << self
      def store
        OoAuth.nonce_store || fail(ConfigurationError, 'no nonce store set')
      end

      def remember(value, timestamp)
        store.create(value, timestamp)
      end
      alias :create :remember
      
      def generate
        new(OoAuth.generate_nonce, Time.now.utc.to_i)
      end
    end
    
    def initialize(value, timestamp)
      raise ArgumentError, 'nonce value cannot be blank' if value.blank?
      raise ArgumentError, 'nonce value too big' if value.size > MAX_LENGTH
      timestamp = timestamp.to_i
      raise ArgumentError, 'illegal nonce timestamp' if timestamp <= 0
      @value, @timestamp = value, timestamp
    end
    
    def save
      self.class.create(value, timestamp) ? true : false
    end
    
  end
end