
require 'ed25519'

module Ccrypto
  module Ruby
    
    class ED25519PublicKey < Ccrypto::ED25519PublicKey

    end

    class ED25519KeyBundle
      include Ccrypto::ED25519KeyBundle

      include TR::CondUtils

      include TeLogger::TeLogHelper
      teLogger_tag :ed25519_kb

      def initialize(kp)
        @nativeKeypair = kp
      end

      def public_key
        if @pubKey.nil?
          @pubKey = ED25519PublicKey.new(@nativeKeypair.verify_key)
        end
        @pubKey
      end

      def private_key
        ED25519PrivateKey.new(@nativeKeypair)
      end

    end # ED25519KeyBundle

    class ED25519Engine
      include TeLogger::TeLogHelper
      teLogger_tag :ed25519_eng

      def initialize(*args, &block)
        @config = args.first 
        teLogger.debug "Config : #{@config}"
      end

      def generate_keypair(&block)
        teLogger.debug "Generating ED25519 keypair"
        ED25519KeyBundle.new(Ed25519::SigningKey.generate)
      end

      def sign(val)
         
        raise KeypairEngineException, "Keypair is required" if @config.keypair.nil?
        raise KeypairEngineException, "ED25519 keypair is required" if not @config.keypair.is_a?(ED25519KeyBundle)

        kp = @config.keypair

        res = kp.nativeKeypair.sign(val)
        teLogger.debug "Data of length #{val.length} signed using ED25519"

        res

      end

      def self.verify(pubKey, val, sign)
        case pubKey
        when Ccrypto::ED25519PublicKey
          uPubKey = pubKey
        else
          raise KeypairEngineException, "Unsupported public key '#{pubKey.class}' for ED25519 operation"
        end

        begin
          uPubKey.verify(sign, val)
        rescue Ed25519::VerifyError => ex
          false
        end
      end

    end

  end
end
