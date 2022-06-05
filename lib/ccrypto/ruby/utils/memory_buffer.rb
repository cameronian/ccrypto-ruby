

module Ccrypto
  module Ruby
    class MemoryBuffer

      def initialize(*args,&block)
        @buf = StringIO.new
        @buf.binmode
      end

      def bytes
        @buf.string
      end

      def pos
        @buf.pos
      end

      def length
        @buf.length
      end

      def rewind
        @buf.rewind
      end

      def dispose(wcnt = 32)
        
        len = @buf.length
        cnt = 0
        loop do
          @buf.rewind
          @buf.write(SecureRandom.random_bytes(len))

          cnt += 1
          break if cnt >= wcnt
        end

        @buffer = nil
        GC.start

      end

      def write(val)
        @buf.write(val) 
      end

      def read(len)
        @buf.read(len)
      end

      def respond_to_missing?(mtd, *args, &block)
        @buf.respond_to?(mtd, *args, &block)
      end

      def equals?(val)
        bytes == val
      end

    end
  end
end
