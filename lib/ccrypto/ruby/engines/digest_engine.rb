
require_relative '../data_conversion'

module Ccrypto
  module Ruby
    class DigestEngine
      include Ccrypto::Ruby::DataConversion
      include TR::CondUtils
      
      SupportedDigest = [
        Ccrypto::SHA1.provider_info("sha1"),
        Ccrypto::SHA224.provider_info("sha224"),
        Ccrypto::SHA256.provider_info("sha256"),
        Ccrypto::SHA384.provider_info("sha384"),
        Ccrypto::SHA512.provider_info("sha512"),
        Ccrypto::SHA512_224.provider_info("sha512-224"),
        Ccrypto::SHA512_256.provider_info("sha512-256"),
        Ccrypto::SHA3_224.provider_info("sha3-224"),
        Ccrypto::SHA3_256.provider_info("sha3-256"),
        Ccrypto::SHA3_384.provider_info("sha3-384"),
        Ccrypto::SHA3_512.provider_info("sha3-512"),
        Ccrypto::SHAKE128.provider_info("shake128"),
        Ccrypto::SHAKE256.provider_info("shake256"),
        Ccrypto::BLAKE2b512.provider_info("BLAKE2b512"),
        Ccrypto::BLAKE2s256.provider_info("BLAKE2s256"),
        Ccrypto::SM3.provider_info("SM3"),
        Ccrypto::RIPEMD160.provider_info("RIPEMD160"),
        Ccrypto::WHIRLPOOL.provider_info("whirlpool")
      ]


      def self.supported
        SupportedDigest
      end

      def self.is_supported?(eng)
        res = supported.include?(eng)
        begin
          res = digest(eng) if not res
        rescue DigestEngineException => ex
          res = false
        end

        res
      end

      def self.instance(*args, &block)
        conf = args.first
        if not_empty?(conf.provider_config)
          logger.debug "Creating digest engine #{conf.provider_config}"
          DigestEngine.new(OpenSSL::Digest.new(conf.provider_config))
        else
          raise DigestEngineException, "Given digest config #{conf.algo} does not have provider key mapping. Most likely this config is not supported by provider #{Ccrypto::Ruby::Provider.provider_name}"
        end
      end

      def self.logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :ruby_digest
        end
        @logger
      end
      def logger
        self.class.logger
      end

      def self.digest(key)
        
        res = engineKeys[key]
        if is_empty?(res)
          logger.debug "No digest available for #{key}"
          raise DigestEngineException, "Not supported digest engine #{key}"
        else
          logger.debug "Found digest #{key.to_sym}"
          DigestEngine.new(OpenSSL::Digest.new(res.provider_config))
        end

      end

      def self.engineKeys
        if @engineKeys.nil?
          @engineKeys = {}
          supported.map do |e|
            @engineKeys[e.algo.to_sym] = e
          end
        end
        @engineKeys
      end

      def initialize(inst)
        @inst = inst
      end

      def native_digest_engine
        @inst
      end
      alias_method :native_instance, :native_digest_engine

      def digest(val, output = :binary)
        digest_update(val)
        digest_final(output)
      end

      def digest_update(val)
        case val
        when MemoryBuffer
          @inst.update(val.bytes)
        else
          @inst.update(val)
        end
      end

      def digest_final(output = :binary)
        
        res = @inst.digest
        @inst.reset
        case output
        when :hex
          to_hex(res)
        when :b64
          to_b64(res)
        else
          res
        end
      end

      def reset
        @inst.reset
      end

    end
  end
end
