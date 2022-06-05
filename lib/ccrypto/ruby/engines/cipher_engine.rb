
require_relative '../data_conversion'

module Ccrypto
  module Ruby
    class CipherEngine
      include TR::CondUtils
      include DataConversion

      include TeLogger::TeLogHelper

      teLogger_tag :r_cipher_eng

      def self.supported_ciphers
        if @sCipher.nil?
          @sCipher = OpenSSL::Cipher.ciphers
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

        teLogger.debug "to_openssl_spec #{spec}"
        case spec.algo
        when :blowfish
          res << "bf"
        else
          res << spec.algo
        end

        res << spec.keysize if not_empty?(spec.keysize) and spec.keysize.to_i > 0 and not spec.is_algo?(:chacha20) and not spec.is_algo?(:seed) and not spec.is_algo?(:sm4) and not spec.is_algo?(:blowfish)

        res << spec.mode 

        teLogger.debug "to_openssl_spec #{res}"

        res.join("-")
        
      end

      def initialize(*args, &block)
        @spec = args.first

        #teLogger = TteLogger.new
        teLogger.debug "Cipher spec : #{@spec}"

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
          teLogger.debug "Operation encrypt"
          @cipher.encrypt
        when :decrypt, :dec
          teLogger.debug "Operation decrypt"
          @cipher.decrypt
        else
          raise Ccrypto::CipherEngineException, "Cipher operation (encrypt/decrypt) must be given"
        end


        if @spec.has_iv?
          teLogger.debug "IV from spec"
          @cipher.iv = @spec.iv
          teLogger.debug "IV : #{to_hex(@spec.iv)}"
        else
          teLogger.debug "Generate random IV"
          @spec.iv = @cipher.random_iv
          teLogger.debug "IV : #{to_hex(@spec.iv)}"
        end


        if @spec.has_key?
          teLogger.debug "Key from spec"
          case @spec.key
          when Ccrypto::SecretKey
            @cipher.key = @spec.key.to_bin
          when String
            @cipher.key = @spec.key
          else
            raise Ccrypto::CipherEngineException, "Unknown key type for processing #{@spec.key}"
          end
        else
          teLogger.debug "Generate random Key"
          @spec.key = @cipher.random_key
        end


        if @spec.is_mode?(:gcm)

          if not_empty?(@spec.auth_data) 
            teLogger.debug "Setting auth data"
            @cipher.auth_data = @spec.auth_data
          end

          if not_empty?(@spec.auth_tag) 
            raise CipherEngineException, "Tag length of 16 bytes is expected" if @spec.auth_tag.bytesize != 16
            teLogger.debug "Setting auth tag"
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

    end
  end
end
