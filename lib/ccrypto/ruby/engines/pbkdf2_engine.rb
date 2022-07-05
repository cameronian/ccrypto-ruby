
require_relative '../data_conversion'

module Ccrypto
  module Ruby
    class PBKDF2Engine
      include TR::CondUtils
      include DataConversion

      def initialize(conf, &block)
        raise KDFEngineException, "PBKDF2 config is expected" if not conf.is_a?(Ccrypto::PBKDF2Config)
        raise KDFEngineException, "Output bit length (outBitLength) value is not given or not a positive value (#{conf.outBitLength})" if is_empty?(conf.outBitLength) or conf.outBitLength <= 0

        @config = conf
        if is_empty?(@config.salt)
          @config.salt = SecureRandom.random_bytes(16)
        end
      end

      def derive(input, output = :binary)

        @config.digest = default_digest if is_empty?(@config.digest)
        digest = init_digest(@config.digest)

        logger.debug "Digest : #{@config.digest}"
        logger.debug "Iterations : #{@config.iter}"
        logger.debug "Out byte length : #{@config.outBitLength/8}"

        res = OpenSSL::KDF.pbkdf2_hmac(input, salt: @config.salt, iterations: @config.iter, length: @config.outBitLength/8, hash: digest)  

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
        if DigestEngine.is_supported?(algo)
          conf = DigestEngine.engineKeys[algo]
          if not_empty?(conf)
            OpenSSL::Digest.new(conf.provider_config)
          else
            raise DigestEngineException, "Algo config '#{algo}' not found"
          end
        else
          raise DigestEngineException, "Digest algo '#{algo}' is not supported"
        end
      end

      def default_digest
        :sha3_256
      end

      def logger
        if @logger.nil?
          @logger = TeLogger::Tlogger.new
          @logger.tag = :pbkdf2
        end
        @logger
      end

    end
  end
end
