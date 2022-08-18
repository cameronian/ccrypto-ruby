

module Ccrypto
  class X509CSR
    include TR::CondUtils

    include TeLogger::TeLogHelper
    teLogger_tag :r_csr

    def initialize(csr)
      @nativeCSR = csr
    end

    def to_bin
      @nativeCSR.to_der
    end

    def equal?(csr)
      if not_empty?(csr)
        case csr
        when String
          @nativeCSR.to_der == csr
        when OpenSSL::X509::Request
          @nativeCSR.to_der == csr.to_der
        when Ccrypto::X509CSR
          @nativeCSR.to_der == csr.to_bin
        else
          raise X509CSRException, "Unknown CSR type #{csr.class}"
        end
      else 
        @nativeCSR == csr
      end
    end

    def method_missing(mtd, *args, &block)
      @nativeCSR.send(mtd, *args, &block)
    end

    def csr_info
      if @csrInfo.nil?
        @csrInfo = parseCSR(@nativeCSR)
      end
      @csrInfo
    end

    def parseCSR(csrBin)

      case csrBin
      when String
        csr = OpenSSL::X509::Request.new(csrBin)
      when Ccrypto::X509CSR
        csr = csrBin.nativeCSR
      else
        raise X509CSREngineException, "Unknown CSR to parse #{csrBin}"
      end

      raise X509CSRSignatureInvalid, "CSR signature is not valid!" if not csr.verify(csr.public_key)

      certProf = Ccrypto::X509::CertProfile.new

      csr.subject.to_a.each do |k,v,a|
        case k
        when "CN"
          certProf.owner_name = v
        when "O"
          certProf.org = v
        when "OU"
          certProf.org_unit = v
        when "emailAddress"
          certProf.email = v
        end
      end

      certProf.public_key = csr.public_key 
      csr.attributes.each do |att|
        teLogger.debug "Processing attribute ID #{att.oid}"
        #p att.oid
        #p att.value

        att.value.each do |v|
          case v
          when OpenSSL::ASN1::Sequence
            v.value.each do |vv|
              #p vv.value[0]
              #p vv.value[1]
              tv = OpenSSL::ASN1.decode(vv.value[1].value)
              case tv
              when OpenSSL::ASN1::Sequence
                tvv = tv.to_a
                tvv.each do |tt|
                  case tt.tag
                  when 1
                    # email
                    certProf.email = tt.value
                  when 2
                    # dns
                    certProf.dns_name = tt.value
                  when 6
                    # uri
                    certProf.uri = tt.value
                  when 7
                    # ip address
                    v = tt.value
                    case v.size
                    when 4
                      ip = v.unpack('C*').join('.')
                    when 6
                      ip = v.unpack('n*').map { |o| sprintf("%X", o) }.join(':')
                    else
                      raise X509EngineException, "Neither IPv4 or IPv6 is given as IP address attributes"
                    end
                    certProf.ip_addr = ip

                  else
                    raise X509EngineException, "Unsupported CSR attributes value #{tt.tag}"
                  end
                  #p tt.tag
                  #p tt.value
                end

              when OpenSSL::ASN1::OctetString
                ## custom extension

                certProf.custom_extension[vv.value[0].value] = { value: vv.value[1].value, type: :string, critical: false }
                #cert.add_extension(OpenSSL::X509::Extension.new(vv.value[0].value,vv.value[1].value, false))

              else
                teLogger.error "Unsupported extension type #{tv.class} in target CSR"
                #raise X509EngineException, "Unknown extension type #{tv.class}"
              end
            end

          when OpenSSL::ASN1::OctetString
          #  ## custom attributes
          #  cert.add_extension(OpenSSL::X509::Extension.new(att.oid,v.value, false))

          #  certProf.custom_attributes[att.oid] = { value: v.value, type: :string }
            certProf.custom_extension[att.oid] = { value: v.value, type: :string, critical: false }

          else
            #raise X509EngineException, "Given attribute #{att.oid} has value of type #{v.class}. Not able to handle"
            teLogger.error "Given attribute #{att.oid} has value of type #{v.class}. Not able to handle"
          end
        end

      end

      certProf

    end

  end
end
