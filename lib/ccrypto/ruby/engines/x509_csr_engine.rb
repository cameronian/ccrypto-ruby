
require 'openssl'
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

module Ccrypto
  module Ruby
    class X509CSREngine
      include TR::CondUtils

      include TeLogger::TeLogHelper
      teLogger_tag :r_csr

      def initialize(csrProfile)
        @csrProfile = csrProfile
      end

      def generate(privKey, &block)

        cp = @csrProfile
        csr = OpenSSL::X509::Request.new
        csr.version = 0
        csr.subject = to_subject(cp)

        case cp.public_key
        when Ccrypto::PublicKey
          pubKey = cp.public_key.native_pubKey
        else
          raise X509CSREngineException, "Public key type '#{cp.public_key.class}' is not supported"
        end

        if pubKey.is_a?(OpenSSL::PKey::EC::Point)
          # ECC patch
          pub = OpenSSL::PKey::EC.new(pubKey.group)
          pub.public_key = pubKey
          csr.public_key = pub
        else
          csr.public_key = pubKey
        end

        exts = []
        exts << OpenSSL::X509::ExtensionFactory.new.create_extension('subjectAltName', "email:#{cp.email.join(",email:")}") if not_empty?(cp.email)
        exts << OpenSSL::X509::ExtensionFactory.new.create_extension('subjectAltName', "IP:#{cp.ip_addr.join(",IP:")}") if not_empty?(cp.ip_addr)
        exts << OpenSSL::X509::ExtensionFactory.new.create_extension('subjectAltName', "DNS:#{cp.dns_name.join(",DNS:")}") if not_empty?(cp.dns_name)
        exts << OpenSSL::X509::ExtensionFactory.new.create_extension('subjectAltName', "URI:#{cp.uri.join(",URI:")}") if not_empty?(cp.uri)

        if not_empty?(cp.custom_extension) and cp.custom_extension.is_a?(Hash)
          teLogger.debug "custom extension"
          cp.custom_extension.each do |k,v|
            case v[:type]
            when :string 
              exts << OpenSSL::X509::Extension.new(k, OpenSSL::ASN1::OctetString.new(v[:value]), v[:critical])
            else
              raise X509CSREngineException, "Unsupported custom extension type #{v[:type]}"
            end
          end
        end


        attrVal = OpenSSL::ASN1::Set [OpenSSL::ASN1::Sequence(exts)]
        csr.add_attribute OpenSSL::X509::Attribute.new('extReq', attrVal)
        csr.add_attribute OpenSSL::X509::Attribute.new('msExtReq', attrVal)

        if not_empty?(cp.additional_attributes) and cp.additional_attributes.is_a?(Hash)
          teLogger.debug "addtinal attributes"
          cp.additional_attributes.each do |k,v|
            case v[:type]
            when :string
              csr.add_attribute OpenSSL::X509::Attribute.new(k, OpenSSL::ASN1::Set.new([OpenSSL::ASN1::OctetString.new(v[:value])]))
            else
              raise X509CSREngineException, "Unknown additional attribute type #{v[:type]}"
            end
          end
        end
       

        case privKey
        when Ccrypto::KeyBundle
          pkey = privKey.private_key.native_privKey
        when Ccrypto::PrivateKey
          pkey = privKey.native_privKey
        else
          raise X509CSREngineException, "Unsupported signing key #{privKey}"
        end
        
        gcsr = csr.sign(pkey, DigestEngine.instance(cp.hashAlgo).native_instance)

        Ccrypto::X509CSR.new(gcsr)

      end

      private
      def to_subject(csrProf)
        res = []
        res << ["CN", csrProf.owner_name]
        res << ["O", csrProf.org] if not_empty?(csrProf.org)
        csrProf.org_unit.each do |ou|
          res << ["OU", ou]
        end

        e = csrProf.email.first
        if not_empty?(e)
          res << ["emailAddress", e]
        end

        OpenSSL::X509::Name.new(res)
      end

    end
  end
end
