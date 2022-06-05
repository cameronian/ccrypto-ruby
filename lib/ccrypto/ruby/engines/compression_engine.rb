

module Ccrypto
  module Ruby
    class Compression

      include TeLogger::TeLogHelper

      teLogger_tag :r_compression

      def initialize(*args, &block)

        @config = args.first
        raise CompressionError, "Compress Config is expected. Given #{@config}" if not @config.is_a?(Ccrypto::CompressionConfig)
        
        if block

          outPath = block.call(:out_path)
          if is_empty?(outPath)
            outFile = block.call(:out_file) 
            raise CompressionError, "Given out_file required to support write() call" if not outFile.respond_to?(:write)
            @out = outFile
          else
            @out = Tempfile.new(SecureRandom.hex(24)) 
          end

          @intBufSize = block.call(:int_buf_size) || 102400

        else
          @intBufSize = 102400

        end

        case @config.level
        when :best_compression
          teLogger.debug "Best compression"
          @eng = Zlib::Deflate.new(Zlib::BEST_COMPRESSION)
        when :best_speed
          teLogger.debug "Best compression"
          @eng = Zlib::Deflate.new(Zlib::BEST_SPEED)
        when :no_compression
          teLogger.debug "No compression"
          @eng = Zlib::Deflate.new(Zlib::NO_COMPRESSION)
        else
          teLogger.debug "Default compression"
          @eng = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION)
        end

      end

      def update(val)
        @eng.deflate(val, Zlib::SYNC_FLUSH)
      end

      def final
        
      end

    end
  end
end
