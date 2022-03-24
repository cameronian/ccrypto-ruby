
require_relative '../data_conversion'

module Ccrypto
  module Ruby
    class CipherEngine
      include TR::CondUtils
      include DataConversion

      def self.supported_ciphers
        if @sCipher.nil?
          @sCipher = OpenSSL::Cipher.ciphers
          #@sCipher.map! { |v| 
          #  f = v.split("-")
          #  algo = f[0]

          #  if algo == "id"
          #    nil
          #  else

          #    if f.length > 2
          #      ks = f[1]
          #      mode = f[2].to_s.downcase.to_sym
          #    else
          #      e = f[1]
          #      if e.to_i > 0
          #        ks = e
          #      else
          #        mode = e.to_s.downcase.to_sym
          #      end
          #      #mode = f[1].to_s.downcase.to_sym
          #    end

          #    cc = Ccrypto::CipherConfig.new(algo) do |k|
          #      case k
          #      when :keysize
          #        ks.to_i
          #      when :mode
          #        mode
          #      when :ivLength
          #        if mode == :gcm
          #          12
          #        else
          #          16
          #        end
          #      end
          #    end

          #    cc.provider_config = v
          #    cc

          #  end
          #}

          #@sCipher.delete_if { |e| e == nil }
        end

        @sCipher

      end

      def self.is_supported_cipher?(c)
        case c
        when String
          supported_ciphers.include?(c)  
        when Hash
          spec = to_openssl_spec(c)
          begin
            OpenSSL::Cipher.new(spec)
            true
          rescue Exception => ex
            false
          end
        else
          raise Ccrypto::CipherEngineException, "Unsupported input #{c} to check supported cipher"
        end
      end

      def self.to_openssl_spec(spec)
        res = []

        logger.debug "to_openssl_spec #{spec}"
        case spec.algo
        when :blowfish
          res << "bf"
        else
          res << spec.algo
        end

        res << spec.keysize if not_empty?(spec.keysize) and spec.keysize.to_i > 0 and not spec.is_algo?(:chacha20) and not spec.is_algo?(:seed) and not spec.is_algo?(:sm4) and not spec.is_algo?(:blowfish)

        res << spec.mode 

        logger.debug "to_openssl_spec #{res}"

        res.join("-")
        
      end

      def self.logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :ccipher_eng
        end
        @logger
      end
      def logger
        self.class.logger
      end

      def initialize(*args, &block)
        @spec = args.first

        #logger = Tlogger.new
        logger.debug "Cipher spec : #{@spec}"

        begin
          case @spec
          #when String
          #  @cipher = OpenSSL::Cipher.new(@spec)
          when Ccrypto::CipherEngineConfig
            @cipher = OpenSSL::Cipher.new(@spec.provider_config)
          when Ccrypto::DirectCipherConfig
            @cipher = OpenSSL::Cipher.new(self.class.to_openssl_spec(@spec))
          else
            raise Ccrypto::CipherEngineException, "Not supported cipher init type #{@spec.class}"
          end
        rescue OpenSSL::Cipher::CipherError, RuntimeError => ex
          raise Ccrypto::CipherEngineException, ex
        end

        case @spec.cipherOps
        when :encrypt, :enc
          logger.debug "Operation encrypt"
          @cipher.encrypt
        when :decrypt, :dec
          logger.debug "Operation decrypt"
          @cipher.decrypt
        else
          raise Ccrypto::CipherEngineException, "Cipher operation (encrypt/decrypt) must be given"
        end


        if @spec.has_iv?
          logger.debug "IV from spec"
          @cipher.iv = @spec.iv
          logger.debug "IV : #{to_hex(@spec.iv)}"
        else
          logger.debug "Generate random IV"
          @spec.iv = @cipher.random_iv
          logger.debug "IV : #{to_hex(@spec.iv)}"
        end


        if @spec.has_key?
          logger.debug "Key from spec"
          case @spec.key
          when Ccrypto::SecretKey
            @cipher.key = @spec.key.to_bin
          when String
            @cipher.key = @spec.key
          else
            raise Ccrypto::CipherEngineException, "Unknown key type for processing #{@spec.key}"
          end
        else
          logger.debug "Generate random Key"
          @spec.key = @cipher.random_key
        end


        if @spec.is_mode?(:gcm)

          if not_empty?(@spec.auth_data) 
            logger.debug "Setting auth data"
            @cipher.auth_data = @spec.auth_data
          end

          if not_empty?(@spec.auth_tag) 
            raise CipherEngineException, "Tag length of 16 bytes is expected" if @spec.auth_tag.bytesize != 16
            logger.debug "Setting auth tag"
            @cipher.auth_tag = @spec.auth_tag
          end

        end

      end

      def update(val)
        @cipher.update(val) 
      end

      def final(val = nil)
        res = []

        begin

          if not_empty?(val)
            res << @cipher.update(val)
          end

          res << @cipher.final

        rescue Exception => ex
          raise CipherEngineException, ex
        end

        if @spec.is_mode?(:gcm) and @spec.is_encrypt_cipher_mode?
          @spec.auth_tag = @cipher.auth_tag 
        end

        res.join
      end

      def reset
        @cipher.reset
      end

      def logger
        self.class.logger
      end

    end
  end
end
