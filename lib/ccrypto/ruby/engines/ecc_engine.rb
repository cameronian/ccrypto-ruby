
require 'openssl'
if OpenSSL::VERSION < "3.0.0"

module PKeyPatch
  def to_pem; public_key.to_pem end
  def to_der; public_key.to_der end

  #private
  def public_key
    key = ::OpenSSL::PKey::EC.new group
    key.public_key = self
    key
  end
end
OpenSSL::PKey::EC::Point.prepend PKeyPatch

end

require_relative '../keybundle_store/pkcs12'
require_relative '../keybundle_store/pem_store'
require_relative '../ecc_const'

module Ccrypto
  module Ruby

    class ECCPublicKey < Ccrypto::ECCPublicKey

      def to_bin
        if OpenSSL::VERSION < "3.0.0"
          @native_pubKey.to_der
        else
          const = ECCConst[@native_pubKey.group.curve_name]
          # At 01 April 2023
          # at Ruby 3.2.1/OpenSSL gem 3.1.0/OpenSSL 3.0.2
          # The gem has bug that the encoding is incorrect
          OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::ObjectId.new("2.8.8.128.0"),
            OpenSSL::ASN1::Integer.new(0x0100),
            OpenSSL::ASN1::Integer.new(const),
            OpenSSL::ASN1::BitString.new(@native_pubKey.to_bn)
          ]).to_der
        end
      end

      def self.to_key(bin)
        if OpenSSL::VERSION > "3.0.0"
          ek = OpenSSL::PKey::EC.new(bin)
        else
          seq = OpenSSL::ASN1Object.decode(bin).value
          envp = ASN1Object.decode(seq[0]).value
          raise KeypairEngineException, "Not ECC public key" if envp != "2.8.8.8.128.0"
          ver = ASN1Object.decode(seq[1]).value
          raise KeypairEngineException, "Unsupported version" if ver != 0x0100
          cv = ASN1Object.decode(seq[2]).value
          curve = ECCConst.invert[cv]
          raise KeypairEngineException, "Unknown curve '#{curve}'" if curve.nil?
          kv = ASN1Object.decode(seq[3]).value

          ek = OpenSSL::PKey::EC::Point.new(OpenSSL::PKey::EC::Group.new(curve), kv)
        end

        ECCPublicKey.new(ek)
      end

    end

    class ECCKeyBundle
      include Ccrypto::ECCKeyBundle
      include TR::CondUtils

      include PKCS12Store
      include PEMStore

      include TeLogger::TeLogHelper

      teLogger_tag :r_ecc_keybundle

      def initialize(keypair)
        @nativeKeypair = keypair
      end

      def public_key
        if @pubKey.nil?
          #if OpenSSL::VERSION < "3.0.0"
            @pubKey = ECCPublicKey.new(@nativeKeypair.public_key)
          #else
          #  @pubKey = ECCPublicKey.new(@nativeKeypair.public_key.to_bn)
          #end
        end
        @pubKey
      end

      def private_key
        ECCPrivateKey.new(@nativeKeypair)
      end

      def derive_dh_shared_secret(pubKey)

        case pubKey
        when OpenSSL::PKey::EC::Point
          tkey = pubKey
        when Ccrypto::ECCPublicKey
          tkey = pubKey.native_pubKey
          if OpenSSL::VERSION < "3.0.0"
            tkey = tkey.public_key if not tkey.is_a?(OpenSSL::PKey::EC::Point)
          else
            tkey = OpenSSL::PKey::EC.new(tkey)
          end
        else
          raise KeypairEngineException, "Unknown public key type #{pubKey.class}" 
        end

        if OpenSSL::VERSION < "3.0.0"
          raise KeypairEngineException, "OpenSSL::PKey::EC::Point is required. Given #{tkey.inspect}" if not tkey.is_a?(OpenSSL::PKey::EC::Point)
        else
          raise KeypairEngineException, "OpenSSL::PKey::EC is required. Given #{tkey.inspect}" if not tkey.is_a?(OpenSSL::PKey::EC)
        end

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
          begin
            teLogger.debug "Given String to load from storage"
            if is_pem?(bin)
              self.from_pem(bin, &block)
            else
              # binary buffer
              teLogger.debug "Given binary to load from storage"
              self.from_pkcs12(bin,&block)
            end
          rescue Ccrypto::Ruby::PKCS12Store::PKCS12StoreException => ex
            raise KeyBundleStorageException, ex
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
          #false
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

    end

    class ECCEngine
      include TR::CondUtils

      include TeLogger::TeLogHelper

      teLogger_tag :r_ecc

      NotAbleToFigureOutOnOpenSSLv2 = [
        "Oakley-EC2N-3",
        "Oakley-EC2N-4"
      ]

      def self.supported_curves
        if @curves.nil?
          @curves = []
          OpenSSL::PKey::EC.builtin_curves.sort.map { |c| 
            
            next if c[0] =~ /^wap/ or NotAbleToFigureOutOnOpenSSLv2.include?(c[0])

            if c[0] == "prime256v1"
              @curves << Ccrypto::ECCConfig.new(c[0], Ccrypto::KeypairConfig::Algo_Active, true) 
            else
              @curves << Ccrypto::ECCConfig.new(c[0]) 
            end
          }
        end
        @curves
      end

      def initialize(*args, &block)
        @config = args.first 
        raise KeypairEngineException, "1st parameter must be a #{Ccrypto::KeypairConfig.class} object" if not @config.is_a?(Ccrypto::KeypairConfig)
        teLogger.debug "Config #{@config}"
      end

      def generate_keypair(&block)
        teLogger.debug "Generating keypair of curve #{@config.curve}"
        kp = OpenSSL::PKey::EC.generate(@config.curve.to_s) 
        #teLogger.debug "Generated keypair #{kp.inspect}"
        ECCKeyBundle.new(kp)
      end

      def sign(val)
        raise KeypairEngineException, "Keypair is required" if @config.keypair.nil?
        raise KeypairEngineException, "ECC keypair is required" if not @config.keypair.is_a?(ECCKeyBundle)
        kp = @config.keypair
        
        res = kp.nativeKeypair.dsa_sign_asn1(val)
        teLogger.debug "Data of length #{val.length} signed "

        res
      end

      def self.verify(pubKey, val, sign)
        if OpenSSL::VERSION > "3.0.0"
          p pubKey.native_pubKey
          p pubKey.native_pubKey.methods.sort
          uPubKey = pubKey.native_pubKey
          if uPubKey.is_a?(OpenSSL::PKey::EC::Point)
            res = uPubKey.dsa_verify_asn1(val, sign)
            res
          else
            raise KeypairEngineException, "Unsupported public key type '#{uPubKey.class}'"
          end

        else
          # OpenSSL v2 - Ruby 2.x
          uPubKey = pubKey.native_pubKey
          if pubKey.native_pubKey.is_a?(OpenSSL::PKey::EC::Point)
            uPubKey = OpenSSL::PKey::EC.new(uPubKey.group)
            uPubKey.public_key = pubKey.native_pubKey
          end

          res = uPubKey.dsa_verify_asn1(val, sign)
          res
        end
      end

    end
  end
end
