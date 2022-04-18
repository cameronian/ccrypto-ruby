
require_relative '../data_conversion'

module Ccrypto
  module Ruby
    
    class PKCS7EngineException < StandardError; end

    class PKCS7Engine
      include TR::CondUtils
      include DataConversion

      def initialize(config)
        @config = config
        raise PKCS7EngineException, "Ccrypto::PKCS7Config is expected" if not @config.is_a?(Ccrypto::PKCS7Config)
      end

      def sign(val, outFormat = :bin, &block)
        validate_input(val, "signing") 
        privKey = @config.keybundle.private_key

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

        res = OpenSSL::PKCS7.sign(@config.x509_cert.nativeX509, privKey, val, caCerts, flag) 
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
            if certVerified
              logger.debug "Certificate : #{c} accepted by application"
              store.add_cert(c)
            else
              logger.debug "Certificate : #{c} rejected by application"
            end
          else
            logger.debug "Certificate : #{c} passed through (no checking by application)"
            store.add_cert(c)
          end
        end

        if certVerified
          
          if p7.detached?
            logger.debug "Detached signature detected"
            raise PKCS7EngineException, "block is required for detached signature" if not block
            data = block.call(:sign_data)
            p7.data = data
          else
            logger.debug "Attached signature detected"
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
      end

      def decrypt(val, &block)
        validate_input(val, "decrypt") 
      end

      protected
      def validate_input(val, ops)
        raise PKCS7EngineException, "Given data to #{ops} operation is empty" if is_empty?(val) 
        raise PKCS7EngineException, "Keybundle is required for PKCS7 #{ops}" if is_empty?(@config.keybundle)
        raise PKCS7EngineException, "X509_cert is required for PKCS7 #{ops}" if is_empty?(@config.x509_cert)
        raise PKCS7EngineException, "Given key must be a Ccrypto::KeyBundle object" if not @config.keybundle.is_a?(Ccrypto::KeyBundle)
        raise PKCS7EngineException, "Given x509_cert must be a Ccrypto::X509Cert object" if not @config.x509_cert.is_a?(Ccrypto::X509Cert)
      end

      private
      def logger
        if @logger.nil?
          @logger = Tlogger.new
          @logger.tag = :pkcs7_engine
        end
        @logger
      end
    end
  end
end
