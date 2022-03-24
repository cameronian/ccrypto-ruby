
require_relative 'asn1_object'

module Ccrypto
  module Ruby

    class ASN1Engine
      include TR::CondUtils

      def self.build(*args, &block)
        type = args.first
        val = args[1]
        case type
        when :oid
          ASN1Object.new(type, OpenSSL::ASN1::ObjectId.new(val))
        when :seq
          ASN1Object.new(type, OpenSSL::ASN1::Sequence.new(val))
        when :str, :utf8_str
          ASN1Object.new(type, OpenSSL::ASN1::UTF8String.new(val))
        when :octet_str
          ASN1Object.new(type, OpenSSL::ASN1::OctetString.new(val))
        when :int
          ASN1Object.new(type, OpenSSL::ASN1::Integer.new(val))
        when :bin
          ASN1Object.new(type, OpenSSL::ASN1::BitString.new(val))
        when :date, :time, :generalize_time
          ASN1Object.new(type, OpenSSL::ASN1::GeneralizedTime.new(val))
        else
          raise ASN1EngineException, "Unknown ASN1 object type '#{type.class}'"
        end
      end

      def self.to_value(*args, &block)
        val = args.first
        expectedType = args[1]
        v = OpenSSL::ASN1.decode(val).value
        if not_empty?(expectedType)
          case expectedType
          when :int
            if v.is_a?(OpenSSL::BN)
              v.to_i
            else
              v
            end
          else
            v
          end
        else
          if v.is_a?(OpenSSL::BN)
            v.to_i
          else
            v
          end
        end
      end

      def self.asn1_length(*args, &block)
        
        val = args.first
        if not_empty?(val)
          
          v = val
          if v.is_a?(ASN1Object)
            v = v.native_asn1
          end

          totalLen = 0
          begin
            OpenSSL::ASN1.traverse(v) do |depth,offset,headerLen,length,constructed,tagClass,tag|
              totalLen = headerLen+length
              break
            end
          rescue StandardError => ex
          rescue OpenSSL::ASN1::ASN1Error => ex
            raise ASN1EngineException, ex
          end

          totalLen

        else
          0
        end


      end

      def self.openssl_to_asn1object(oasn1)
        case oasn1
        when OpenSSL::ASN1::ObjectId
          type = :oid
        when OpenSSL::ASN1::Sequence
          type = :seq
        when OpenSSL::ASN1::UTF8String
          type = :str
        when OpenSSL::ASN1::OctetString
          type = :octet_str
        when OpenSSL::ASN1::Integer
          type = :int
        when OpenSSL::ASN1::BitString
          type = :bin
        when OpenSSL::ASN1::GeneralizedTime
          type = :time
        end

        ASN1Object.new(:oid, oasn1)
      end

    end
  end
end
