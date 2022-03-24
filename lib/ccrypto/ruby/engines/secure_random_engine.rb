

module Ccrypto
  module Ruby
    class SecureRandomEngine

      def self.random_bytes(size)
        SecureRandom.random_bytes(size)
      end

      def self.random_hex(size)
        SecureRandom.hex(size)
      end

      def self.random_b64(size)
        SecureRandom.base64(size)
      end

      def self.random_uuid
        SecureRandom.uuid
      end

      def self.random_alphanum(size)
        SecureRandom.alphanumeric(size)
      end

      def self.random_number(val = nil)
        SecureRandom.rand(val)
      end
      self.singleton_class.alias_method :rand, :random_number

    end
  end
end
