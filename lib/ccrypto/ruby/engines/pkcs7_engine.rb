
require_relative '../data_conversion'

module Ccrypto
  module Ruby
    
    class PKCS7EngineException < StandardError; end

    class PKCS7Engine
      include TR::CondUtils
      include DataConversion

      include TeLogger::TeLogHelper

      teLogger_tag :r_p7

      def initialize(config)
        @config = config
        raise PKCS7EngineException, "Ccrypto::PKCS7Config is expected" if not @config.is_a?(Ccrypto::PKCS7Config)
      end

      def sign(val, outFormat = :bin, &block)
        validate_input(val, "signing") 
        validate_key_must_exist("signing")
        raise PKCS7EngineException, "signerCert is required for PKCS7 sign operation" if is_empty?(@config.signerCert)
        raise PKCS7EngineException, "Given signerCert must be a Ccrypto::X509Cert object" if not @config.signerCert.is_a?(Ccrypto::X509Cert)

        privKey = @config.private_key.native_privKey

        caCerts = []
        attached = true
        if block
          caCerts = block.call(:ca_certs)
          detachedSign = block.call(:detached_sign)
          attached = ! detachedSign if is_bool?(detachedSign)
        end

        caCerts = [] if caCerts.nil?
        attached = true if is_empty?(attached) and not is_bool?(attached)

        if not attached
          flag = OpenSSL::PKCS7::BINARY | OpenSSL::PKCS7::DETACHED
        else
          flag = OpenSSL::PKCS7::BINARY
        end

        res = OpenSSL::PKCS7.sign(@config.signerCert.nativeX509, privKey, val, caCerts, flag) 
        case outFormat
        when :b64
          to_b64(res.to_der)
        when :hex
          to_hex(res.to_der)
        else
          res.to_der
        end
      end

      def verify(val, inForm = :bin, &block)
        validate_input(val, "verify") 

        case inForm
        when :b64
          v = from_b64(val)
        when :hex
          v = from_hex(val)
        else
          v = val
        end

        p7 = OpenSSL::PKCS7.new(v)

        certVerified = true
        store = OpenSSL::X509::Store.new
        p7.certificates.each do |c|
          if block
            certVerified = block.call(:verify_certificate, c)
            if is_empty?(certVerified)
              teLogger.debug "Certificate with subject #{c.subject.to_s} / Issuer: #{c.issuer.to_s} / SN: #{c.serial.to_s(16)} passed through (no checking by application). Assumed good cert."
              store.add_cert(c)
              certVerified = true
            else
              if certVerified
                teLogger.debug "Certificate with subject #{c.subject.to_s} / Issuer: #{c.issuer.to_s} / SN: #{c.serial.to_s(16)} accepted by application"
                store.add_cert(c)
              else
                teLogger.debug "Certificate with subject #{c.subject.to_s} / Issuer: #{c.issuer.to_s} / SN: #{c.serial.to_s(16)} rejected by application"
              end
            end
          else
            teLogger.debug "Certificate with subject #{c.subject.to_s} / Issuer: #{c.issuer.to_s} / SN: #{c.serial.to_s(16)} passed through (no checking by application)"
            store.add_cert(c)
          end
        end

        if certVerified
          
          if p7.detached?
            teLogger.debug "Detached signature detected during signature verification"
            raise PKCS7EngineException, "block is required for detached signature" if not block
            data = block.call(:signed_data)
            p7.data = data
          else
            teLogger.debug "Attached signature detected during signature verification"
          end

          res = p7.verify([], store, nil, OpenSSL::PKCS7::NOVERIFY)

          if block
            block.call(:verification_result, res)
            if res and not p7.detached?
              block.call(:attached_data, p7.data)
            end
          end

          res

        else
          certVerified
        end

      end

      def encrypt(val, &block)
        validate_input(val, "encrypt") 
        raise PKCS7EngineException, "At least one recipient_cert is required for PKCS7 encrypt" if is_empty?(@config.recipient_certs)
        
        recps = @config.recipient_certs.map do |c|
          raise PKCS7EngineException, "Given recipient_cert must be a Ccrypto::X509Cert object" if not c.is_a?(Ccrypto::X509Cert)
          c.nativeX509
        end

        if block
          cipher = block.call(:cipher)
          teLogger.debug "Application given cipher : #{cipher}"
        end

        cipher = "AES-256-CBC" if is_empty?(cipher)

        teLogger.debug "Setting P7 encryption cipher #{cipher}"
        cip = OpenSSL::Cipher.new(cipher)

        begin
          OpenSSL::PKCS7.encrypt(recps, val, cip, OpenSSL::PKCS7::BINARY)
        rescue OpenSSL::PKCS7::PKCS7Error => ex
          raise PKCS7EngineException, ex
        end

      end

      def decrypt(val, &block)
        validate_input(val, "decrypt") 
        validate_key_must_exist("decrypt")

        raise PKCS7EngineException, "certForDecryption is required for PKCS7 decrypt operation" if is_empty?(@config.certForDecryption)
        raise PKCS7EngineException, "Given certForDecryption must be a Ccrypto::X509Cert object" if not @config.certForDecryption.is_a?(Ccrypto::X509Cert)

        p7 = OpenSSL::PKCS7.new(val)
        p7.decrypt(@config.private_key.native_privKey, @config.certForDecryption.nativeX509)
      end

      protected
      def validate_input(val, ops)
        raise PKCS7EngineException, "Given data to #{ops} operation is empty" if is_empty?(val) 
      end

      def validate_key_must_exist(ops)
        #raise PKCS7EngineException, "Keybundle is required for PKCS7 #{ops}" if is_empty?(@config.keybundle)
        #raise PKCS7EngineException, "Given key must be a Ccrypto::KeyBundle object" if not @config.keybundle.is_a?(Ccrypto::KeyBundle)
        raise PKCS7EngineException, "Private key is required for PKCS7 #{ops}" if is_empty?(@config.private_key)
        raise PKCS7EngineException, "Given private key must be a Ccrypto::PrivateKey object" if not @config.private_key.is_a?(Ccrypto::PrivateKey)
      end

      #def validate_cert_must_exist(ops)
      #  raise PKCS7EngineException, "signerCert is required for PKCS7 #{ops}" if is_empty?(@config.signerCert)
      #  raise PKCS7EngineException, "Given signerCert must be a Ccrypto::X509Cert object" if not @config.signerCert.is_a?(Ccrypto::X509Cert)
      #end

    end
  end
end
