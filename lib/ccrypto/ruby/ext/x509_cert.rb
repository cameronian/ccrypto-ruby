

module Ccrypto
  class X509Cert
    include TR::CondUtils

    def equal?(cert)
      if is_empty?(cert) 
        if is_empty?(@nativeX509)
          true
        else
          false
        end
      else
        @nativeX509.to_der == cert.to_der
      end
    end

    def method_missing(mtd, *args, &block)
      @nativeX509.send(mtd, *args, &block)
    end

  end
end
