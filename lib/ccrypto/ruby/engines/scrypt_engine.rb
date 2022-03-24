
require_relative '../data_conversion'

module Ccrypto
  module Ruby
    class ScryptEngine
      include DataConversion
      include TR::CondUtils

      def initialize(conf, &block)
        raise KDFEngineException, "KDF config is expected" if not conf.is_a?(Ccrypto::KDFConfig)
        raise KDFEngineException, "Output bit length (outBitLength) value is not given or not a positive value (#{conf.outBitLength})" if is_empty?(conf.outBitLength) or conf.outBitLength <= 0
        @config = conf

        if is_empty?(@config.salt)
          @config.salt = SecureRandom.random_bytes(16)
        end
      end

      def derive(input, output = :binary)
        res = OpenSSL::KDF.scrypt(input, salt: @config.salt, N: @config.cost, r: @config.blockSize, p: @config.parallel, length: @config.outBitLength/8)  
        case output
        when :hex
          to_hex(res)
        when :b64
          to_b64(res)
        else
          res
        end
      end

    end
  end
end
