

module Ccrypto
  class SecretKey

    def to_bin
      case @key
      when String
        @key
      else
        @key.key
      end
    end

    def length
      to_bin.length
    end

    def equals?(key)
      to_bin == key
    end

  end
end
