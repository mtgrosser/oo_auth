module OoAuth
  class Nonce
    class RedisStore < AbstractStore
      attr_reader :redis, :namespace, :ttl

      def initialize(options = {})
        options.symbolize_keys!
        @namespace = options.delete(:namespace)
        @ttl = options.delete(:ttl) || 15.minutes
        @redis = Redis.new(options)
      end

      def remember(nonce)
        return nonce if @redis.set(key(nonce), '1', { nx: true, ex: ttl })
        false
      rescue Errno::ECONNREFUSED
        false
      end
      
      protected

      def key(nonce)
        "#{@namespace}:oo_auth_nonce:#{nonce.timestamp}:#{nonce.value}"
      end      
      
    end
  end
end