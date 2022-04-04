
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
      include Ccrypto::ECCKeyBundle
      include TR::CondUtils

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

      def to_storage(format, &block)
        case format
        when :pkcs12, :p12
          raise KeypairEngineException, "Block is required" if not block
          gcert = block.call(:cert)
          raise KeypairEngineException, "PKCS12 requires the X.509 certificate" if gcert.nil? or is_empty?(gcert)

          case gcert
          when String
            begin
              cert = OpenSSL::X509::Certificate.new(gcert)
            rescue Exception => ex
              raise KeypairEngineException, ex
            end
          when OpenSSL::X509::Certificate
            cert = gcert
          when Ccrypto::X509Cert
            cert = gcert.nativeX509
          else
            raise KeypairEngineException, "Unknown user certificate type #{gcert}"
          end

          ca = block.call(:certchain) || [cert]
          ca = ca.collect { |c|
            case c
            when Ccrypto::X509Cert
              c.nativeX509
            else
              c
            end
          }
          pass = block.call(:p12_pass)
          name = block.call(:p12_name) || "Ccrypto ECC "
          res = OpenSSL::PKCS12.create(pass, name, @nativeKeypair, cert, ca)
          res.to_der

        when :pem 
          if block
            kcipher = block.call(:pem_cipher) || "AES-256-GCM"
            kpass = block.call(:pem_pass)
          end

          kcipher = "AES-256-GCM" if is_empty?(kcipher)

          if not_empty?(kpass)
            kCipher = OpenSSL::Cipher.new(kcipher)
            @nativeKeypair.export(kCipher, kpass)
          else
            @nativeKeypair.export
          end

        else
          raise KeypairEngineException, "Unknown storage format #{format}"
        end
      end

      def self.from_storage(bin, &block)
        raise KeypairEngineException, "Given data to load is empty" if is_empty?(bin)

        case bin
        when String
          logger.debug "Given String to load from storage" 
          if is_pem?(bin)
            begin
              # try with no password first to check if the keystore is really encrypted
              # If not the library will prompt at command prompt which might halt the flow of program
              pKey = OpenSSL::PKey.read(bin,"")
              ECCKeyBundle.new(pKey)
            rescue OpenSSL::PKey::PKeyError => ex
              raise KeypairEngineException, "block is required" if not block
              pass = block.call(:pem_pass)
              begin
                pKey = OpenSSL::PKey.read(bin, pass)
                ECCKeyBundle.new(pKey)
              rescue OpenSSL::PKey::PKeyError => exx
                raise KeypairEngineException, exx
              end
            end

          else
            # binary buffer
            logger.debug "Given binary to load from storage" 
            raise KeypairEngineException, "block is required" if not block
            pass = block.call(:p12_pass)
            p12 = OpenSSL::PKCS12.new(bin, pass)
            [ECCKeyBundle.new(p12.key), Ccrypto::X509Cert.new(p12.certificate), p12.ca_certs.collect { |c| Ccrypto::X509Cert.new(c) }]
          end
        else
          raise KeypairEngineException, "Unsupported bin format #{bin}"
        end

      end

      def self.is_pem?(bin)
        if is_empty?(bin)
          false
        else
          begin
            (bin =~ /BEGIN/) != nil
          rescue ArgumentError => ex
            if ex.message =~ /invalid byte sequence/
              false
            else
              raise KeypairEngineException, ex
            end
          end
        end
      end

      def self.logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :ecc_keybundle
        end
        @logger
      end
      def logger
        self.class.logger
      end

      def equal?(kp)
        if kp.respond_to?(:to_der)
          @nativeKeypair.to_der == kp.to_der
        else
          false
        end
      end

      def method_missing(mtd, *args, &block)
        #if @nativeKeypair.respond_to?(mtd)
          logger.debug "Sending to nativeKeypair #{mtd}"
          @nativeKeypair.send(mtd,*args, &block)
        #else
        #  super
        #end
      end

      def respond_to_missing?(mtd, *args, &block)
        @nativeKeypair.respond_to?(mtd)
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
