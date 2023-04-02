
require_relative '../data_conversion'

module Ccrypto
  module Ruby
    
    module PKCS12Store
      include TR::CondUtils
      include DataConversion

      class PKCS12StoreException < KeyBundleStorageException; end

      module ClassMethods

        def from_pkcs12(input, &block)
          raise PKCS12StoreException, "Input cannot be empty" if is_empty?(input) 

          raise PKCS12StoreException, "Block is required" if not block

          inForm = block.call(:in_format)
          case inForm
          when :b64
            inp = from_b64(input)
          when :hex
            inp = from_hex(input)
          else
            inp = input
          end

          pass = block.call(:store_pass)
          raise PKCS12StoreException, "Password cannot be empty" if is_empty?(pass)

          begin
            p12 = OpenSSL::PKCS12.new(inp, pass)
            case p12.key
            when OpenSSL::PKey::EC
              [Ccrypto::Ruby::ECCKeyBundle.new(p12.key), Ccrypto::X509Cert.new(p12.certificate), p12.ca_certs.collect{ |c| Ccrypto::X509Cert.new(c) }]
            else
              [Ccrypto::Ruby::RSAKeyBundle.new(p12.key), Ccrypto::X509Cert.new(p12.certificate), p12.ca_certs.collect{ |c| Ccrypto::X509Cert.new(c) }]
            end
          rescue Exception => ex
            raise PKCS12StoreException, ex
          end

        end
      end
      def self.included(klass)
        klass.extend(ClassMethods)
      end
      
      def to_pkcs12(&block)

        raise PKCS12StoreException, "Block is required" if not block

        ucert = block.call(:cert)
        raise PKCS12StoreException, "Certificate is required" if is_empty?(ucert)

        case ucert
        when String
           begin
             cert = OpenSSL::X509::Certificate.new(ucert)
           rescue Exception => ex
             raise PKCS12StoreException, ex
           end
        when OpenSSL::X509::Certificate
          cert = ucert
        when Ccrypto::X509Cert
          cert = ucert.nativeX509
        else
          raise PKCS12StoreException, "Unknown given certificate to store in P12 : #{cert}"
        end

        ca = block.call(:certchain) 
        ca = [cert] if is_empty?(ca)
        ca = ca.collect do |c|
          case c
          when Ccrypto::X509Cert
            c.nativeX509
          else
            c
          end
        end

        pass = block.call(:store_pass) 
        raise PKCS12StoreException, "Password is required" if is_empty?(pass)

        name = block.call(:key_name)
        name = "Ccrypto KeyBundle" if is_empty?(name)

        keypair = block.call(:keypair)
        raise PKCS12StoreException, "Keypair is required" if is_empty?(keypair)

        res = OpenSSL::PKCS12.create(pass, name, keypair, cert, ca)

        outFormat = block.call(:out_format)
        outFormat = :bin if is_empty?(outFormat)

        case outFormat
        when :b64
          to_b64(res.to_der)
        when :to_hex
          to_hex(res.to_der)
        else
          res.to_der
        end

      end

    end

  end
end
