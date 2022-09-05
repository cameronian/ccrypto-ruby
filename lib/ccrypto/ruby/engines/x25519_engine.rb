
require 'x25519'

module Ccrypto
  module Ruby
    
    class X25519PublicKey < Ccrypto::X25519PublicKey

    end

    class X25519KeyBundle
      include Ccrypto::X25519KeyBundle

      include TR::CondUtils

      include TeLogger::TeLogHelper
      teLogger_tag :x25519_kb

      def initialize(kp)
        @nativeKeypair = kp
      end

      def public_key
        if @pubKey.nil?
          @pubKey = X25519PublicKey.new(@nativeKeypair.public_key)
        end
        @pubKey
      end

      def private_key
        X25519PrivateKey.new(@nativeKeypair)
      end

      def derive_dh_shared_secret(pubKey)
        
        case pubKey
        when Ccrypto::X25519PublicKey
          uPubKey = pubKey.native_pubKey
        else
          raise KeypairEngineException, "Unknown X25519 public key type '#{pubKey.class}'"
        end

        @nativeKeypair.diffie_hellman(uPubKey).to_bytes
      end

    end # X25519KeyBundle

    class X25519Engine
      include TeLogger::TeLogHelper
      teLogger_tag :x25519_eng

      def initialize(*args, &block)
        @config = args.first 
        teLogger.debug "Config : #{@config}"
      end

      def generate_keypair(&block)
        teLogger.debug "Generating X25519 keypair"
        X25519KeyBundle.new(X25519::Scalar.generate)
      end

    end

  end
end
