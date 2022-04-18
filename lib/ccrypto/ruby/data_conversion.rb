require 'base64'

module Ccrypto
  module Ruby
    module DataConversion

      def to_hex(bin, opts = { })
        if not bin.nil?  
          bin.each_byte.map { |b| b.to_s(16).rjust(2,'0') }.join
        else
          bin
        end
      end

      def from_hex(str, opts = { })
        if not str.nil?
          str.scan(/../).map { |x| x.hex.chr }.join
        else
          str
        end
      end

      def to_b64(bin, opts = { })
        if not bin.nil?
          if not (opts[:strict].nil? and opts[:strict] == true)
            Base64.encode64(bin)
          else
            Base64.strict_encode64(bin)
          end
        else
          bin
        end
      end

      def from_b64(str, opts = { })
        if not str.nil?
          if not (opts[:strict].nil? and opts[:strict] == true)
            Base64.decode64(str)
          else
            Base64.strict_decode64(str)
          end
        else
          str
        end
      end

      def to_int_array(str, opts = { })
        if not str.nil?
          str.each_char.map { |c| c.ord }
        else
          str
        end
      end

      # 
      # Add the methods to class level
      #
      def self.included(klass)
        klass.class_eval <<-END
        extend Ccrypto::Ruby::DataConversion
        END
      end

    end
    # end module Converter
    #
  end
end 
