
require 'openssl'

module Ccrypto
  module Ruby

    class SecretSharingEngine
      def initialize(*args, &block)
        @config = args.first 
        raise SecretSharingException, "SecretSharingConfig is required" if not @config.is_a?(Ccrypto::SecretSharingConfig)
        raise SecretSharingException, "split_into value must be more than 1" if not @config.split_into.to_i > 1
        raise SecretSharingException, "required_parts value (#{@config.required_parts}) must be less than or equal split_into value (#{@config.split_into})." if not @config.required_parts.to_i < @config.split_into.to_i
      end

      def split(secVal)

        case secVal
        when MemoryBuffer
          data = secVal.bytes
        when String
          data = secVal
        when Ccrypto::SecretKey
          data = secVal.to_bin
        else
          raise SecretSharingException, "Unknown how to process split for #{secVal.class}"
        end

        eng = ShamirSharing.new(@config.required_parts.to_i, data)
        shares = []
        (1..@config.split_into.to_i).each do |i|
          res = eng.compute_share(i)
          res[1] = res[1].map { |v| v.chr }.join
          shares << res
        end        
        shares
      end

      def self.combine(req, parts)

        parts.each do |k,v|
          parts[k] = v.chars.map(&:ord)
        end

        ss = ShamirSharing.new(req)
        ss.recover_secretdata(parts.to_a)
      end
    end
    

    #
    # This code is borrowed from PolyPasswordHasher-Ruby project at https://github.com/PolyPasswordHasher/PolyPasswordHasher-Ruby
    # 
    class ShamirSharing
      attr_reader :_coefficients
      attr_reader :secretdata

      def initialize(threshold, secretdata=nil)
        @threshold = threshold
        @secretdata = secretdata
        @_coefficients = []

        if secretdata
          secretdata.each_char do |secretbyte|
            thesecoefficients = secretbyte+OpenSSL::Random.random_bytes(@threshold-1)
            @_coefficients << thesecoefficients
          end
        end
      end

      def is_valid_share?(share)
        raise "Share is of incorrect length: #{share.size}" if share.size !=2
        raise "Must initialize coefficient before checking is_valid_share?" unless @_coefficients
        raise "Must initialize coefficient before checking is_valid_share?" if @_coefficients.size != share[1].size

        x  = share[0]
        fx = share[1]

        correctshare = compute_share(x)

        correctshare == share
      end

      def compute_share(x)
        raise "x should be integer" unless x.class == Fixnum
        raise "x must be between 1 and 255" if x <= 0 || x  >256
        raise "@_coefficient must be initialized" if @_coefficients.empty?

        sharebytes = []

        @_coefficients.each do |thiscoefficient|
          thisshare = _f(x,thiscoefficient)
          sharebytes << thisshare
        end

        return x, sharebytes
      end

      def recover_secretdata(shares)
        newshares = []

        shares.each do |share|
          newshares << share unless newshares.include?(share)
        end

        shares = newshares

        if @threshold > shares.size
          raise "Threshold: #{@threshold} is smaller than the number of uniquie shares: #{shares.size}"
        end

        if @secretdata
          raise "Recovoring secretdata when some is stored. Use check_share instead"
        end

        xs = []

        shares.each do |share|
          if xs.include?(share[0])
            raise "Different shares with the same first byte: #{share[0]}"
          end

          if share[1].size != shares[0][1].size
            raise "Shares have different lengths!"
          end

          xs << share[0]
        end

        mycoefficients = []
        mysecretdata = ''

        shares[0][1].size.times.each do |byte_to_use|
          fxs = []
          shares.each do |share|
            fxs << share[1][byte_to_use]
          end

          resulting_poly = _full_lagrange(xs,fxs)

          if resulting_poly[0..@threshold-1] + [0]*(shares.size - @threshold) != resulting_poly
            raise "Share do not match. Cannot decode"
          end

          mycoefficients << resulting_poly.map{|p| p.chr}.join

          mysecretdata += resulting_poly[0].chr
        end

        @_coefficients = mycoefficients
        @secretdata = mysecretdata
      end

      private
      def _f(x, coefs_bytes)
        raise "invalid share index value. cannot be 0" if x == 0

        accumulator = 0

        x_i = 1

        coefs_bytes.each_byte do |c|
          accumulator = _gf256_add(accumulator, _gf256_mul(c, x_i))
          x_i = _gf256_mul(x_i, x)
        end

        return accumulator
      end

      def _multiply_polynomials(a,b)
        resultterms = []

        termpadding = []

        b.each do |bterm|
          thisvalue = termpadding.clone

          a.each do |aterm|
            val = _gf256_mul(aterm, bterm)
            thisvalue << _gf256_mul(aterm, bterm)
          end

          resultterms = _add_polynomials(resultterms, thisvalue)

          termpadding << 0
        end

        return resultterms
      end

      def _add_polynomials(a,b)
        if a.size < b.size
          a = a + [0]*(b.size - a.size)
        elsif a.size > b.size
          b = b + [0]*(a.size - b.size)
        end

        result = []

        a.size.times do |pos|
          result << _gf256_add(a[pos], b[pos])
        end

        return result
      end

      def _full_lagrange(xs, fxs)
        returnedcoefficients = []

        fxs.size.times do |i|
          this_polynomial = [1]

          fxs.size.times do |j|
            next if i == j

            denominator = _gf256_sub(xs[i], xs[j])

            this_term = [_gf256_div(xs[j], denominator), _gf256_div(1, denominator)]

            this_polynomial = _multiply_polynomials(this_polynomial, this_term)
          end

          this_polynomial = _multiply_polynomials(this_polynomial, [fxs[i]]) if fxs[i]

          returnedcoefficients = _add_polynomials(returnedcoefficients, this_polynomial)
        end

        return returnedcoefficients

      end

      GF256_EXP = [
        0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff,
        0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35,
        0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4,
        0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa,
        0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26,
        0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31,
        0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc,
        0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd,
        0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7,
        0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88,
        0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f,
        0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a,
        0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0,
        0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
        0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec,
        0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0,
        0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2,
        0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41,
        0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0,
        0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75,
        0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e,
        0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
        0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf,
        0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54,
        0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09,
        0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca,
        0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91,
        0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
        0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c,
        0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17,
        0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd,
        0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6, 0x01] 

      GF256_LOG = [
        0x00, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1a, 0xc6,
        0x4b, 0xc7, 0x1b, 0x68, 0x33, 0xee, 0xdf, 0x03,
        0x64, 0x04, 0xe0, 0x0e, 0x34, 0x8d, 0x81, 0xef,
        0x4c, 0x71, 0x08, 0xc8, 0xf8, 0x69, 0x1c, 0xc1,
        0x7d, 0xc2, 0x1d, 0xb5, 0xf9, 0xb9, 0x27, 0x6a,
        0x4d, 0xe4, 0xa6, 0x72, 0x9a, 0xc9, 0x09, 0x78,
        0x65, 0x2f, 0x8a, 0x05, 0x21, 0x0f, 0xe1, 0x24,
        0x12, 0xf0, 0x82, 0x45, 0x35, 0x93, 0xda, 0x8e,
        0x96, 0x8f, 0xdb, 0xbd, 0x36, 0xd0, 0xce, 0x94,
        0x13, 0x5c, 0xd2, 0xf1, 0x40, 0x46, 0x83, 0x38,
        0x66, 0xdd, 0xfd, 0x30, 0xbf, 0x06, 0x8b, 0x62,
        0xb3, 0x25, 0xe2, 0x98, 0x22, 0x88, 0x91, 0x10,
        0x7e, 0x6e, 0x48, 0xc3, 0xa3, 0xb6, 0x1e, 0x42,
        0x3a, 0x6b, 0x28, 0x54, 0xfa, 0x85, 0x3d, 0xba,
        0x2b, 0x79, 0x0a, 0x15, 0x9b, 0x9f, 0x5e, 0xca,
        0x4e, 0xd4, 0xac, 0xe5, 0xf3, 0x73, 0xa7, 0x57,
        0xaf, 0x58, 0xa8, 0x50, 0xf4, 0xea, 0xd6, 0x74,
        0x4f, 0xae, 0xe9, 0xd5, 0xe7, 0xe6, 0xad, 0xe8,
        0x2c, 0xd7, 0x75, 0x7a, 0xeb, 0x16, 0x0b, 0xf5,
        0x59, 0xcb, 0x5f, 0xb0, 0x9c, 0xa9, 0x51, 0xa0,
        0x7f, 0x0c, 0xf6, 0x6f, 0x17, 0xc4, 0x49, 0xec,
        0xd8, 0x43, 0x1f, 0x2d, 0xa4, 0x76, 0x7b, 0xb7,
        0xcc, 0xbb, 0x3e, 0x5a, 0xfb, 0x60, 0xb1, 0x86,
        0x3b, 0x52, 0xa1, 0x6c, 0xaa, 0x55, 0x29, 0x9d,
        0x97, 0xb2, 0x87, 0x90, 0x61, 0xbe, 0xdc, 0xfc,
        0xbc, 0x95, 0xcf, 0xcd, 0x37, 0x3f, 0x5b, 0xd1,
        0x53, 0x39, 0x84, 0x3c, 0x41, 0xa2, 0x6d, 0x47,
        0x14, 0x2a, 0x9e, 0x5d, 0x56, 0xf2, 0xd3, 0xab,
        0x44, 0x11, 0x92, 0xd9, 0x23, 0x20, 0x2e, 0x89,
        0xb4, 0x7c, 0xb8, 0x26, 0x77, 0x99, 0xe3, 0xa5,
        0x67, 0x4a, 0xed, 0xde, 0xc5, 0x31, 0xfe, 0x18,
        0x0d, 0x63, 0x8c, 0x80, 0xc0, 0xf7, 0x70, 0x07]


      def _gf256_add(a, b)
        val = a ^ b
        val
      end

      def _gf256_sub(a,b)
        _gf256_add(a,b)
      end

      def _gf256_mul(a,b)
        a = a.to_i
        b = b.to_i
        if a == 0 || b == 0
          return 0
        else
          GF256_EXP[(GF256_LOG[a] + GF256_LOG[b]) % 255]
        end
      end

      def _gf256_div(a,b)
        if a == 0
          return 0
        elsif b == 0
          raise ZeroDivisionError
        else
          GF256_EXP[(GF256_LOG[a] - GF256_LOG[b]) % 255]
        end
      end
    end # class ShamirSharing

  end
end
