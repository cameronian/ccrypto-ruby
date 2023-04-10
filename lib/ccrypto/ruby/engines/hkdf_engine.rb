
require_relative '../data_conversion'

module Ccrypto
  module Ruby
    class HKDFEngine
      include DataConversion
      include TR::CondUtils

      def initialize(*args, &block)
        @config = args.first

        raise KDFEngineException, "KDF config is expected" if not @config.is_a?(Ccrypto::KDFConfig)
        raise KDFEngineException, "Output bit length (outBitLength) value is not given or not a positive value (#{@config.outBitLength})" if is_empty?(@config.outBitLength) or @config.outBitLength <= 0


        @config.salt = SecureRandom.random_bytes(16) if is_empty?(@config.salt)
      end

      def derive(input, output = :binary)

        digest = init_digest(@config.digest)

        @config.info = "" if @config.info.nil?

        res = OpenSSL::KDF.hkdf(input, salt: @config.salt, info: @config.info, length: @config.outBitLength/8, hash: digest)

        case output
        when :hex
          to_hex(res)
        when :b64
          to_b64(res)
        else
          res
        end
      end

      private
      def init_digest(algo)
        DigestEngine.instance(algo).native_instance
      end

    end
  end
end
