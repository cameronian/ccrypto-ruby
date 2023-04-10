
require_relative '../data_conversion'

module Ccrypto
  module Ruby
    class HMACEngine
      include TR::CondUtils
      include DataConversion

      def initialize(*args,&block)
        @config = args.first

        raise HMACEngineException, "HMAC config is expected" if not @config.is_a?(Ccrypto::HMACConfig) 

        raise HMACEngineException, "Signing key is required" if is_empty?(@config.key)
        raise HMACEngineException, "Secret key as signing key is required. Given #{@config.key.class}" if not @config.key.is_a?(Ccrypto::SecretKey)

        dig = DigestEngine.instance(@config.digest).native_instance

        @hmac = OpenSSL::HMAC.new(@config.key.to_bin, dig)

      end

      def hmac_update(val)
        @hmac.update(val) 
      end

      def hmac_final
        @hmac.digest
      end

      def hmac_digest(val, output = :binary)
        hmac_update(val)
        res = hmac_final

        @hmac.reset

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
