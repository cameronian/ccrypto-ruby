

module Ccrypto
  module Ruby
    class NativeHelper

      def self.is_byte_array?(dat)
        if not dat.nil?
          dat.is_a?(String) and (dat.count('01') == dat.size)
        else
          false
        end
      end

    end
  end
end
