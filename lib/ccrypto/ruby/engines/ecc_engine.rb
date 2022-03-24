
require 'openssl'
module PKeyPatch
  def to_pem; public_key.to_pem end
  def to_der; public_key.to_der end

  #private
  def public_key
    puts "called"
    key = ::OpenSSL::PKey::EC.new group
    key.public_key = self
    key
  end
end
OpenSSL::PKey::EC::Point.prepend PKeyPatch


module Ccrypto
  module Ruby

    class ECCPublicKey < Ccrypto::ECCPublicKey
      
      #def initialize(pubKey)
      #  @pubKey = pubKey
      #end

      def to_bin
        @native_pubKey.to_der
      end

      #def native_pubKey
      #  @pubKey
      #end

      def self.to_key(bin)
        ek = OpenSSL::PKey::EC.new(bin)
        #logger.debug "to_key : #{ek}"
        ECCPublicKey.new(ek)
      end

      def self.logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :ecc_pubkey
        end
        @logger
      end

    end

    class ECCKeyBundle
      include Ccrypto::KeyBundle

      def initialize(keypair)
        @nativeKeypair = keypair
      end

      def public_key
        if @pubKey.nil?
          @pubKey = ECCPublicKey.new(@nativeKeypair.public_key)
        end
        @pubKey
      end

      def private_key
        @nativeKeypair
      end

      def derive_dh_shared_secret(pubKey)

        case pubKey
        when OpenSSL::PKey::EC::Point
          tkey = pubKey
        when Ccrypto::ECCPublicKey
          tkey = pubKey.native_pubKey
          tkey = tkey.public_key if not tkey.is_a?(OpenSSL::PKey::EC::Point)
        else
          raise KeypairEngineException, "Unknown public key type #{pubKey.class}" 
        end

        raise KeypairEngineException, "OpenSSL::PKey::EC::Point is required. Given #{tkey.inspect}" if not tkey.is_a?(OpenSSL::PKey::EC::Point)
        @nativeKeypair.dh_compute_key(tkey) 
      end

      def is_public_key_equal?(pubKey)

        case pubKey
        when OpenSSL::PKey::EC
          targetKey = pubKey
        when ECCKeyBundle
          targetKey = pubKey.public_key
        when ECCPublicKey
          targetKey = pubKey.native_pubKey
        else
          raise KeypairEngineException, "Unknown public key type #{pubKey.class}" 
        end

        public_key.to_bin == targetKey.to_der
      end

      def logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :ecc_keybundle
        end
        @logger
      end

      def method_missing(mtd, *args, &block)
        #if @nativeKeypair.respond_to?(mtd)
          logger.debug "Sending to nativeKeypair #{mtd}"
          @nativeKeypair.send(mtd,*args, &block)
        #else
        #  super
        #end
      end
    end

    class ECCEngine
      include TR::CondUtils

      def self.supported_curves
        if @curves.nil?
          @curves = OpenSSL::PKey::EC.builtin_curves.map { |c| Ccrypto::ECCConfig.new(c[0]) }
        end
        @curves
      end

      def initialize(*args, &block)
        @config = args.first 
        raise KeypairEngineException, "1st parameter must be a #{Ccrypto::KeypairConfig.class} object" if not @config.is_a?(Ccrypto::KeypairConfig)
        logger.debug "Config #{@config}"
      end

      def generate_keypair(&block)
        logger.debug "Generating keypair of curve #{@config.curve}"
        kp = OpenSSL::PKey::EC.generate(@config.curve.to_s) 
        #logger.debug "Generated keypair #{kp.inspect}"
        ECCKeyBundle.new(kp)
      end

      def sign(val)
        raise KeypairEngineException, "Keypair is required" if @config.keypair.nil?
        raise KeypairEngineException, "ECC keypair is required" if not @config.keypair.is_a?(ECCKeyBundle)
        kp = @config.keypair
        
        res = kp.nativeKeypair.dsa_sign_asn1(val)
        logger.debug "Data of length #{val.length} signed "

        res
      end

      def self.verify(pubKey, val, sign)
        res = pubKey.native_pubKey.dsa_verify_asn1(val, sign)
        res
      end

      private
      def logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :ecc_engine
        end
        @logger
      end

    end
  end
end
