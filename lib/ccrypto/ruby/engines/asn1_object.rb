

module Ccrypto
  module Ruby
    class ASN1Object < Ccrypto::ASN1Object

      def to_bin
        case @asn1
        when OpenSSL::ASN1::Sequence
          seq = OpenSSL::ASN1::Sequence.new(@asn1.map { |e| e.to_der })
          seq.to_der
        else
          @asn1.to_der
        end
      end

    end
  end
end
