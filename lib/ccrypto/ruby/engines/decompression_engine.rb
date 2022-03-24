

module Ccrypto
  module Ruby
    class Decompression

      def initialize(*args, &block)
        if block

          outPath = block.call(:out_path)
          if is_empty?(outPath)
            outFile = block.call(:out_file) 
            raise CompressionError, "Given out_file required to support write() call" if not outFile.respond_to?(:write)
            @out = outFile
          else
            @out = Tempfile.new(SecureRandom.hex(16)) 
          end

          @intBufSize = block.call(:int_buf_size) || 102400

        else
          @intBufSize = 102400

        end

        @eng = Zlib::Inflate.new

        #@in = Tempfile.new(SecureRandom.hex(16)) 
      end

      def update(val)
        begin
          @eng.inflate(val)
        rescue Zlib::DataError
        end
      end

      def final
       
        #eng = Zlib::Inflate.new

        #@in.seek(0)

        #intBuf = false
        #if @out.nil?
        #  @out = StringIO.new
        #  intBuf = true
        #end

        #chunk = 102400
        #loop do
        #  compressed = @in.read(chunk)
        #  res = eng.inflate(compressed) #, Zlib::SYNC_FLUSH)
        #  @out.write(res)

        #  break if @in.eof?
        #end

        #if intBuf
        #  @out.string
        #else
        #  @out
        #end

      end


    end
  end
end
