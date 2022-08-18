
require_relative 'ruby/engines/ecc_engine'
require_relative 'ruby/engines/digest_engine'
require_relative 'ruby/engines/x509_engine'
require_relative 'ruby/engines/x509_csr_engine'

require_relative 'ruby/engines/scrypt_engine'
require_relative 'ruby/engines/hkdf_engine'
require_relative 'ruby/engines/pbkdf2_engine'

require_relative 'ruby/engines/secure_random_engine'
require_relative 'ruby/engines/cipher_engine'

require_relative 'ruby/utils/comparator'
require_relative 'ruby/utils/memory_buffer'
require_relative 'ruby/utils/native_helper'

require_relative 'ruby/engines/asn1_engine'
require_relative 'ruby/engines/compression_engine'
require_relative 'ruby/engines/decompression_engine'

require_relative 'ruby/engines/secret_key_engine'
require_relative 'ruby/engines/hmac_engine'

require_relative 'ruby/engines/data_conversion_engine'

require_relative 'ruby/engines/secret_sharing_engine'

require_relative 'ruby/engines/pkcs7_engine'

require_relative 'ruby/engines/rsa_engine'

module Ccrypto
  module Ruby
    class Provider

      def self.provider_name
        "ruby"
      end

      def self.algo_instance(*args, &block)
        config = args.first

        if config.is_a?(Class) or config.is_a?(Module)
          if config == Ccrypto::ECCConfig
            ECCEngine
          elsif config == Ccrypto::RSAConfig
            RSAEngine
          elsif config == Ccrypto::ECCKeyBundle
            ECCKeyBundle
          elsif config == Ccrypto::RSAKeyBundle
            RSAKeyBundle
          elsif config == Ccrypto::DigestConfig
            DigestEngine
          elsif config == Ccrypto::SecureRandomConfig
            SecureRandomEngine
          elsif config == Ccrypto::CipherConfig
            CipherEngine
          elsif config == Ccrypto::ECCPublicKey
            Ccrypto::Ruby::ECCPublicKey
          elsif config == Ccrypto::KeyConfig
            Ccrypto::Ruby::SecretKeyEngine
          elsif config == Ccrypto::SecretSharingConfig
            SecretSharingEngine
          elsif config == Ccrypto::X509::CSRProfile
            X509CSREngine
          else
            raise CcryptoProviderException, "Config class '#{config}' is not supported for provider '#{self.provider_name}'"
          end
        else
          case config
          when Ccrypto::ECCConfig
            ECCEngine.new(*args, &block)
          when Ccrypto::RSAConfig
            RSAEngine.new(*args, &block)
          when Ccrypto::DigestConfig
            DigestEngine.instance(*args, &block)
          when Ccrypto::X509::CertProfile
            X509Engine.new(*args,&block)
          when Ccrypto::X509::CSRProfile
            X509CSREngine.new(*args,&block)
          when Ccrypto::ScryptConfig
            ScryptEngine.new(*args,&block)
          when Ccrypto::HKDFConfig
            HKDFEngine.new(*args, &block)
          when Ccrypto::PBKDF2Config
            PBKDF2Engine.new(*args, &block)
          when Ccrypto::CipherConfig
            CipherEngine.new(*args, &block)
          when Ccrypto::HMACConfig
            HMACEngine.new(*args, &block)
          when Ccrypto::SecretSharingConfig
            SecretSharingEngine.new(*args,&block)
          when Ccrypto::PKCS7Config
            PKCS7Engine.new(*args, &block)
          else
            raise CcryptoProviderException, "Config instance '#{config}' is not supported for provider '#{self.provider_name}'"
          end
        end

        #case config
        #when Ccrypto::ECCConfig.class
        #  puts "ecc config class"
        #  ECCEngine
        #when Ccrypto::ECCConfig
        #  puts "ecc config"
        #  ECCEngine.new(*args, &block)
        #when Ccrypto::DigestConfig.class
        #  puts "digest config class"
        #  DigestEngine
        #when Ccrypto::DigestConfig
        #  puts "digest config"
        #  DigestEngine.instance(*args,&block)
        #else
        #  raise CcryptoProviderException, "Config '#{config}' is not supported for provider '#{self.provider_name}'"
        #end

        #case algo
        #when :ecc
        #  ECCEngine
        #when :x509
        #  if args.length > 1
        #    X509Engine.new(*args[1..-1])
        #  else
        #    X509Engine
        #  end
        #when :scrypt
        #  ScryptEngine.new
        #when :secure_random
        #  SecureRandomEngine
        #else
        #  if DigestEngine.is_supported?(algo)
        #    DigestEngine.instance(algo)
        #  elsif CipherEngine.is_supported_cipher?(algo.to_s)
        #    if args.length > 1 or args[0].is_a?(String)
        #      CipherEngine.new(*args)
        #    else
        #      CipherEngine
        #    end
        #  else
        #    raise CcryptoProviderException, "Algo '#{algo}' is not supported for provider '#{self.provider_name}'"
        #  end
        #end

      end

      def self.asn1_engine(*args, &block)
        ASN1Engine
      end

      def self.util_instance(*args, &block)
        type = args.first
        case type
        when :comparator, :compare
          ComparatorUtil
        when :data_conversion, :converter, :data_converter
          DataConversionEngine

        when :memory_buffer, :membuf, :buffer, :mem
          MemoryBuffer

        when :compression, :compressor
          Compression.new(*(args[1..-1]), &block)

        when :decompression
          Decompression.new(*(args[1..-1]), &block)

        when :native_helper
          NativeHelper

        else
          raise CcryptoProviderException, "Util type #{type} is not supported by provider #{self.provider_name}"
        end
      end

    end
  end
end


