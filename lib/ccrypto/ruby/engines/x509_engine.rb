

module Ccrypto
  module Ruby
    class X509Engine
      include TR::CondUtils

      include TeLogger::TeLogHelper
      teLogger_tag :x509Eng

      def initialize(cert_profile)
        @certProfile = cert_profile
      end

      def generate(issuerKey, &block)

        cp = @certProfile
        cert = OpenSSL::X509::Certificate.new
        cert.version = 2
        cert.serial = OpenSSL::BN.new(cp.serial, 16)
        cert.subject = to_cert_subject

        ext = OpenSSL::X509::ExtensionFactory.new
        ext.subject_certificate = cert

        iss = cp.issuer_cert

        iss = iss.nativeX509 if iss.is_a?(Ccrypto::X509Cert)

        if not_empty?(iss) 
          raise X509EngineException, "Issuer certificate must be X509 Certificate object" if not iss.is_a?(OpenSSL::X509::Certificate)
          cert.issuer = iss.subject
          ext.issuer_certificate = iss

          cp.match_issuer_not_before(iss.not_before)
          cp.match_issuer_not_after(iss.not_after)

        else
          cert.issuer = cert.subject
          ext.issuer_certificate = cert
        end

        cert.not_before = cp.not_before 
        cert.not_after = cp.not_after

        case cp.public_key
        when Ccrypto::PublicKey
          pubKey = cp.public_key.native_pubKey
        else
          raise X509EngineException, "Public key type '#{cp.public_key.class}' is not supported"
        end

        if pubKey.is_a?(OpenSSL::PKey::EC::Point)
          # ECC patch
          pub = OpenSSL::PKey::EC.new(pubKey.group)
          pub.public_key = pubKey
          cert.public_key = pub
        else
          cert.public_key = pubKey
        end

        cert.add_extension(ext.create_extension("basicConstraints","CA:TRUE",true)) if cp.gen_issuer_cert?
        cert.add_extension(ext.create_extension("subjectKeyIdentifier","hash")) if cp.gen_subj_key_id?
        cert.add_extension(ext.create_extension("authorityKeyIdentifier","keyid:always,issuer:always")) if cp.gen_auth_key_id?

        #cert.add_extension(ext.create_extension("keyUsage",to_keyusage,true))
        cp.key_usage.selected.each do |ku,critical|
          teLogger.debug "Setting KeyUsage : #{ku} (#{critical})"
          case ku
          when :crlSign
            cert.add_extension(ext.create_extension("keyUsage","cRLSign",critical))
          else
            cert.add_extension(ext.create_extension("keyUsage",ku.to_s,critical))
          end
        end

       
        #extKeyUsage = to_extkeyusage
        extKeyUsage = []
        cp.ext_key_usage.selected.each do |ku,critical|
          case ku
          when :allPurpose
            #kur << :anyExtendedKeyUsage
            cert.add_extension(ext.create_extension("extendedKeyUsage","anyExtendedKeyUsage",critical)) 
          when :timestamping
            #kur << :timeStamping
            cert.add_extension(ext.create_extension("extendedKeyUsage","timeStamping",critical)) 
          when :ocspSigning
            #kur << :oCSPSigning
            cert.add_extension(ext.create_extension("extendedKeyUsage","oCSPSigning",critical)) 
          when :ipSecIKE
            #kur << :ipsecIKE
            cert.add_extension(ext.create_extension("extendedKeyUsage","ipsecIKE",critical)) 
          when :msCtlsign
            #kur << :msCTLSign
            cert.add_extension(ext.create_extension("extendedKeyUsage","msCTLSign",critical)) 
          when :msEFS
            #kur << :msEfs
            cert.add_extension(ext.create_extension("extendedKeyUsage","msEfs",critical)) 
          else
            #kur << ku
            cert.add_extension(ext.create_extension("extendedKeyUsage",ku.to_s,critical)) 
          end
        end

        cp.domain_key_usage.each do |dku, critical|
          cert.add_extension(ext.create_extension("extendedKeyUsage",dku.to_s,critical)) 
        end

        cert.add_extension(ext.create_extension("subjectAltName","email:#{cp.email.join(",email:")}",false)) if not_empty?(cp.email)
        cert.add_extension(ext.create_extension("subjectAltName","DNS:#{cp.dns_name.join(",DNS:")}",false)) if not_empty?(cp.dns_name)
        cert.add_extension(ext.create_extension("subjectAltName","IP:#{cp.ip_addr.join(",IP:")}",false)) if not_empty?(cp.ip_addr)
        cert.add_extension(ext.create_extension("subjectAltName","URI:#{cp.uri.join(",URI:")}",false)) if not_empty?(cp.uri)

        # try to sync the structure with Java BC output
        # whereby single name = multiple URI however failed
        # If single format is required need more R&D
        #
        #crlDistPoint = []
        #if not_empty?(cp.crl_dist_point)
        #  cnt = 1
        #  cp.crl_dist_point.each do |cdp|
        #    crlDistPoint << "URI.#{cnt}:#{cdp}"
        #    cnt += 1
        #  end
        #end
        #p crlDistPoint.join(",")
        #cert.add_extension(ext.create_extension("crlDistributionPoints","URI:#{crlDistPoint.join(",")}",false)) if not_empty?(crlDistPoint)
        #
        cert.add_extension(ext.create_extension("crlDistributionPoints","URI:#{cp.crl_dist_point.join(",URI:")}",false)) if not_empty?(cp.crl_dist_point)

        aia = []
        aia << "OCSP;URI:#{cp.ocsp_url.join(",OCSP;URI:")}" if not_empty?(cp.ocsp_url)
        aia << "caIssuers;URI:#{cp.issuer_url.join(",caIssuers;URI:")}" if not_empty?(cp.issuer_url)
        cert.add_extension(ext.create_extension("authorityInfoAccess",aia.join(","),false)) if not_empty?(aia)


        case issuerKey
        when Ccrypto::KeyBundle
          privKey = issuerKey.private_key.native_privKey
        when Ccrypto::PrivateKey
          privKey = issuerKey.native_privKey
        else
          raise X509EngineException, "Unsupported issuer key #{issuerKey}"
        end

        res = cert.sign(privKey, DigestEngine.instance(cp.hashAlgo).native_instance)

        Ccrypto::X509Cert.new(res)

      end

      private
      def to_cert_subject
        res = []
        res << ["CN", @certProfile.owner_name]
        res << ["O", @certProfile.org] if not_empty?(@certProfile.org)
        @certProfile.org_unit.each do |ou|
          res << ["OU", ou]
        end

        e = @certProfile.email.first
        if not_empty?(e)
          res << ["emailAddress", e]
        end

        OpenSSL::X509::Name.new(res)
      end

      #def to_keyusage
      #  kur = []
      #  @certProfile.key_usage.selected.each do |ku,critical|
      #    case ku
      #    when :crlSign
      #      cert.add_extension(ext.create_extension("keyUsage",:cRLSign,critical))
      #      #kur << :cRLSign
      #    else
      #      #kur << ku
      #      cert.add_extension(ext.create_extension("keyUsage",ku,critical))
      #    end
      #  end

      #  #kur.join(",")
      #end

      #def to_extkeyusage
      #  kur = []
      #  @certProfile.ext_key_usage.selected.keys.each do |ku|
      #    case ku
      #    when :allPurpose
      #      kur << :anyExtendedKeyUsage
      #    when :timestamping
      #      kur << :timeStamping
      #    when :ocspSigning
      #      kur << :oCSPSigning
      #    when :ipSecIKE
      #      kur << :ipsecIKE
      #    when :msCtlsign
      #      kur << :msCTLSign
      #    when :msEFS
      #      kur << :msEfs
      #    else
      #      kur << ku
      #    end
      #  end

      #  #kur.join(",")
      #  kur
      #end

    end
  end
end
