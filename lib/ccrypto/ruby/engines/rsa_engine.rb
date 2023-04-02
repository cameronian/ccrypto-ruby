
require_relative '../keybundle_store/pkcs12'
require_relative '../keybundle_store/pem_store'

module Ccrypto
  module Ruby
    
    class RSAPublicKey < Ccrypto::RSAPublicKey

      def to_bin
        @native_pubKey.to_der
      end

      def self.to_key(bin)
        rk = OpenSSL::PKey::RSA.new(bin)
        RSAPublicKey.new(rk)
      end

    end # RSAPublicKey

    class RSAKeyBundle 
      include Ccrypto::RSAKeyBundle
      include TR::CondUtils

      include PKCS12Store
      include PEMStore

      include TeLogger::TeLogHelper

      teLogger_tag :r_rsa_keybundle

      def initialize(kp)
        @nativeKeypair = kp
      end

      def public_key
        if @pubKey.nil?
          @pubKey = RSAPublicKey.new(@nativeKeypair.public_key)
        end
        @pubKey
      end

      def private_key
        if @privKey.nil?
          @privKey = Ccrypto::RSAPrivateKey.new(@nativeKeypair)
        end
        @privKey
      end

      def to_storage(format, &block)
        case format
        when :pkcs12, :p12
          to_pkcs12 do |key|
            case key
            when :keypair
              @nativeKeypair
            else
              block.call(key) if block
            end
          end
        when :pem 
          to_pem do |key|
            case key
            when :keypair
              @nativeKeypair
            else
              block.call(key) if block
            end
          end
        else
          raise KeyBundleStorageException, "Unknown storage format #{format}"
        end
       
      end

      def self.from_storage(bin, &block)
        raise KeypairEngineException, "Given data to load is empty" if is_empty?(bin)

        case bin
        when String
          teLogger.debug "Given String to load from storage" 
          if is_pem?(bin)
            self.from_pem(bin, &block)
          else
            # binary buffer
            teLogger.debug "Given binary to load from storage" 
            self.from_pkcs12(bin,&block)
          end
        else
          raise KeyBundleStorageException, "Unsupported input type #{bin}"
        end

      end

      def equal?(kp)
        if kp.respond_to?(:to_der)
          @nativeKeypair.to_der == kp.to_der
        else
          @nativeKeypair == kp
        end
      end

      def method_missing(mtd, *args, &block)
        if @nativeKeypair.respond_to?(mtd)
          teLogger.debug "Sending to nativeKeypair #{mtd}"
          @nativeKeypair.send(mtd,*args, &block)
        else
          super
        end
      end

      def respond_to_missing?(mtd, *args, &block)
        @nativeKeypair.respond_to?(mtd)
      end

    end # RSAKeyBundle

    class RSAEngine
      include TR::CondUtils

      def initialize(*args, &block)
        @config = args.first
        raise KeypairEngineException, "1st parameter must be a #{Ccrypto::KeypairConfig.class} object" if not @config.is_a?(Ccrypto::KeypairConfig)
      end

      def generate_keypair(&block)
        kp = OpenSSL::PKey::RSA.generate(@config.keysize)
        RSAKeyBundle.new(kp)
      end

      def sign(val, &block)
        if block
          pss = block.call(:pss_mode)
          pss = false if is_empty?(pss) or not is_bool?(pss)

          if pss
            sign_pss(val, &block)
          else
            sign_typical(val, &block)
          end
        else
          sign_typical(val, &block)
        end
      end

      def self.verify(pubKey, val, sign, &block)
        if block
          pss = block.call(:pss_mode)
          pss = false if is_empty?(pss) or not is_bool?(pss)

          if pss
            verify_pss(pubKey, val, sign, &block)
          else
            verify_typical(pubKey, val, sign, &block)
          end
        else
          verify_typical(pubKey, val, sign, &block)
        end
      end

      def self.encrypt(pubKey, val, &block)
        raise KeypairEngineException, "Public key is required" if is_empty?(pubKey)

        padding = :oaep
        if block
          padding = block.call(:padding)
        end

        case padding
        when :pkcs1
          padVal = OpenSSL::PKey::RSA::PKCS1_PADDING
        when :oaep
          padVal = OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
        when :no_padding
          padVal = OpenSSL::PKey::RSA::NO_PADDING
        else
          raise KeypairEngineException, "Padding requires either :pkcs1 or :oaep. Default is :oaep"
        end

        pubKey.public_encrypt(val, padVal)
      end

      def decrypt(enc, &block)

        raise KeypairEngineException, "Private key is required" if not @config.has_private_key? 
        raise KeypairEngineException, "RSA private key is required" if not @config.private_key.is_a?(RSAPrivateKey)

        padding = :oaep
        if block
          padding = block.call(:padding)
        end

        case padding
        when :pkcs1
          padVal = OpenSSL::PKey::RSA::PKCS1_PADDING
        when :oaep
          padVal = OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
        when :no_padding
          padVal = OpenSSL::PKey::RSA::NO_PADDING
        else
          raise KeypairEngineException, "Padding requires either :pkcs1 or :oaep. Default is :oaep"
        end

        @config.private_key.private_decrypt(enc, padVal)
      end

      def self.supported_keysizes
        [
          Ccrypto::RSAConfig.new(1024, Ccrypto::KeypairConfig::Algo_NotRecommended), 
          Ccrypto::RSAConfig.new(2048, Ccrypto::KeypairConfig::Algo_Active, true), 
          Ccrypto::RSAConfig.new(4096), 
          Ccrypto::RSAConfig.new(8192)
        ] 
      end



      #####################
      ## Private section ##
      private
      def sign_typical(val, &block)
        
        raise KeypairEngineException, "Private key is required" if not @config.has_private_key? 
        raise KeypairEngineException, "RSA private key is required" if not @config.private_key.is_a?(RSAPrivateKey)

        privKey = @config.private_key

        signHash = "sha256"
        if block
          signHash = block.call(:sign_hash)
        end

        begin
          shash = OpenSSL::Digest.new(signHash)
        rescue Exception => ex
          raise KeypairEngineException, ex
        end

        privKey.sign(shash, val)

      end

      def sign_pss(val, &block)
        
        raise KeypairEngineException, "Private key is required" if not @config.has_private_key? 
        raise KeypairEngineException, "RSA private key is required" if not @config.private_key.is_a?(RSAPrivateKey)

        privKey = @config.private_key

        signHash = "sha256"
        mgf1Hash = "sha256"
        saltLen = :max
        if block
          signHash = block.call(:sign_hash)
          mgf1Hash = block.call("mgf1_hash")
          saltLen = block.call("salt_length")
        end
        mgf1Hash = "sha256" if is_empty?(mgf1Hash)
        saltLen = :max if is_empty?(saltLen)
        signHash = "sha256" if is_empty?(signHash)

        privKey.native_privKey.sign_pss(signHash, val, salt_length: saltLen, mgf1_hash: mgf1Hash)

      end

      def self.verify_typical(pubKey, val, sign, &block)
        uPubKey = pubKey.native_pubKey

        if block
          signHash = block.call(:sign_hash)
        end
        signHash = "sha256" if is_empty?(signHash)

        begin
          shash = OpenSSL::Digest.new(signHash)
        rescue Exception => ex
          raise KeypairEngineException, ex
        end

        res = uPubKey.verify(shash, sign, val)
        res
        
      end

      def self.verify_pss(pubKey, val, sign, &block)
        uPubKey = pubKey.native_pubKey

        signHash = "sha256"
        mgf1Hash = "sha256"
        saltLen = :auto
        if block
          signHash = block.call(:sign_hash)
          mgf1Hash = block.call("mgf1_hash")
          saltLen = block.call("salt_length")
        end
        mgf1Hash = "sha256" if is_empty?(mgf1Hash)
        saltLen = :auto if is_empty?(saltLen)
        signHash = "sha256" if is_empty?(signHash)

        res = uPubKey.verify_pss(signHash, sign, val, salt_length: saltLen, mgf1_hash: mgf1Hash)
        res
        
      end


    end

  end
end
