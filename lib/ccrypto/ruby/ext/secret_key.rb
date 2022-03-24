

module Ccrypto
  class SecretKey

    def to_bin
      p @key
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
      p key
      to_bin == key
    end

  end
end
