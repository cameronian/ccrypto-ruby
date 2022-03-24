

module Ccrypto
  module Ruby
    class SecretKeyEngine

      def self.generate(*args, &block)
        config = args.first

        raise SecretKeyEngineException, "KeyConfig is expected" if not config.is_a?(Ccrypto::KeyConfig) 

        key = SecureRandom.random_bytes(config.keysize/8)

        Ccrypto::SecretKey.new(config.algo, key)
      end
    end
  end
end
