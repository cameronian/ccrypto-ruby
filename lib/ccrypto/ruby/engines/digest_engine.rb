
require_relative '../data_conversion'

module Ccrypto
  module Ruby
    class DigestEngine
      include Ccrypto::Ruby::DataConversion
      include TR::CondUtils

      include TeLogger::TeLogHelper

      teLogger_tag :r_digest
      
      #SupportedDigest = {
      #  sha1: Ccrypto::DigestConfig.new(:sha1, 160).provider_info("sha1"),
      #  Ccrypto::SHA224.provider_info("sha224"),
      #  Ccrypto::SHA256.provider_info("sha256"),
      #  Ccrypto::SHA384.provider_info("sha384"),
      #  Ccrypto::SHA512.provider_info("sha512"),
      #  Ccrypto::SHA512_224.provider_info("sha512-224"),
      #  Ccrypto::SHA512_256.provider_info("sha512-256"),
      #  Ccrypto::SHA3_224.provider_info("sha3-224"),
      #  Ccrypto::SHA3_256.provider_info("sha3-256"),
      #  Ccrypto::SHA3_384.provider_info("sha3-384"),
      #  Ccrypto::SHA3_512.provider_info("sha3-512"),
      #  Ccrypto::SHAKE128.provider_info("shake128"),
      #  Ccrypto::SHAKE256.provider_info("shake256"),
      #  Ccrypto::BLAKE2b512.provider_info("BLAKE2b512"),
      #  Ccrypto::BLAKE2s256.provider_info("BLAKE2s256"),
      #  Ccrypto::SM3.provider_info("SM3")
      #  # deprecated starting OpenSSL v3.0
      #  #Ccrypto::RIPEMD160.provider_info("RIPEMD160"),
      #  #Ccrypto::WHIRLPOOL.provider_info("whirlpool")
      #}


      def self.supported
        if @supportedConf.nil?
          @supportedConf = {}
          supported_digest_symbols.each do |d|
            begin
              teLogger.debug "Checking digest  : #{d}"
              name = d.to_s.gsub("_","-")
              md = OpenSSL::Digest.new(name)
              dig = Ccrypto::DigestConfig.new(:sha1, md.digest_length*8, { provider_config: { algo_name: name } })

              @supportedConf[d] = dig 
              @supportedConf[name] = dig

            rescue Exception => ex
              p ex
            end
          end
        end
        @supportedConf
      end

      def self.supported_digest_symbols
        # no way as of OpenSSL 3.1.2 to return a list of supported digest algo... So manually fix the list
        [:sha1, :sha224, :sha256, :sha384, :sha512, :sha512_224, :sha512_256, :sha3_256, :sha3_384, :sha3_512, :shake128, :shake256, :blake2b512, :blake2s256, :sm3]
      end
        
      def self.is_digest_supported?(eng)
        not find_digest_config(eng).nil?
      end

      def self.find_digest_config(key)
        case key
        when Ccrypto::DigestConfig
          key
        when String, Symbol
          supported[key]
        end
      end

      def self.instance(*args, &block)
        conf = args.first
        digEng = find_digest_config(conf)
        raise DigestEngineException, "Unsupported digest instance '#{conf}'" if digEng.nil?

        DigestEngine.new(OpenSSL::Digest.new(digEng.provider_config[:algo_name]))
      end


      ## 
      # Instance variable
      ##
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
