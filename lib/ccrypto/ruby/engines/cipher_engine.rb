
require_relative '../data_conversion'

module Ccrypto
  module Ruby
    class CipherEngine
      include TR::CondUtils
      include DataConversion

      include TeLogger::TeLogHelper

      teLogger_tag :r_cipher_eng

      NotAbleToFigureOutOnOpenSSLv2 = [
        "aes-128-cbc-hmac-sha1",
        "aes-256-cbc-hmac-sha1",
        "aes-128-cbc-hmac-sha256",
        "aes-256-cbc-hmac-sha256",
        "aes-128-ccm",
        "aes-192-ccm",
        "aes-256-ccm",
        "aria-128-ccm",
        "aria-192-ccm",
        "aria-256-ccm",
        "rc4-hmac-md5"
      ]

      #CherryPick = [
      #  "aes-128-cbc", "aes-192-cbc", "aes-256-cbc",
      #  "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
      #  "aria-128-cbc","aria-192-cbc", "aria-256-cbc",
      #  "aria-128-gcm","aria-192-gcm", "aria-256-gcm",
      #  "camellia-128-cbc","camellia-192-cbc", "camellia-256-cbc",
      #  "camellia-128-ctr","camellia-192-ctr", "camellia-256-ctr",
      #  "chacha20-poly1305"
      #]

      def self.supported_ciphers
        if @sCipher.nil?
          @sCipherStr = []
          @sCipher = []

          OpenSSL::Cipher.ciphers.each do |c|
            
            teLogger.debug "found cipher : #{c}"
            next if c =~ /^id-\w*/ 
            teLogger.debug "loading cipher : #{c}"

            if OpenSSL::VERSION < "3.0.0" and NotAbleToFigureOutOnOpenSSLv2.include?(c)
              teLogger.debug "Running on OpenSSL < v3. Skipping cipher #{c}"
              next
            end

            begin
              co = OpenSSL::Cipher.new(c)
              #teLogger.debug "Algo #{c} : authenticated? #{co.authenticated?}"
              #p co.methods.sort
              cc = c.split("-")
              @sCipherStr << c
              
              algo = cc.first
              exclusion = ["chacha20","sm4"]
              # to find string like aes128, aes256 from openssl
              if not exclusion.include?(algo) and (algo =~ /[0-9]/) != nil
                # match the one before the numbers
                algo = $` 
              end

              native = { algo_str: c }
              keysize = co.key_len*8
              opts = { keysize: keysize, ivLength: co.iv_len, authMode: co.authenticated? }

              if c.downcase =~ /\w*(gcm|ecb|cbc|cfb|cfb1|cfb8|ofb|ctr|ccm|xts|wrap|poly1305)/
                teLogger.debug "Mode extraction : #{$&} / #{$'}"
                # after the match
                if not_empty?($')
                  opts[:mode] = "#{$&}#{$'}"
                else
                  # the match
                  opts[:mode] = $&.downcase
                end
              else
                # no mode defined. Seems defaulted to cbc according to document
                if co.authenticated?
                  opts[:mode] = "gcm"
                else
                  opts[:mode] = "cbc"
                end
              end

              teLogger.debug "Mode : #{opts[:mode]}"
              if opts[:mode] == :xts.to_s
                opts[:min_input_length] = 16
              elsif opts[:mode] == "cbc-hmac-sha1"
                opts[:min_input_length] = 16
                opts[:mandatory_block_size] = 16
              elsif opts[:mode] == "cbc-hmac-sha256"
                opts[:min_input_length] = 32
                opts[:mandatory_block_size] = 32
              elsif opts[:mode] == "wrap"
                case algo
                when "aes"
                  case keysize
                  when 128
                    opts[:min_input_length] = 16
                    opts[:mandatory_block_size] = 8
                  when 192
                    opts[:min_input_length] = 24
                    opts[:mandatory_block_size] = 8
                  when 256
                    opts[:min_input_length] = 32
                    opts[:mandatory_block_size] = 8
                  end
                when "des3", "des"
                  opts[:min_input_length] = 8
                  opts[:mandatory_block_size] = 8
                end
              end

              conf = Ccrypto::CipherConfig.new(algo, opts)
              conf.native_config = native

              Ccrypto::SupportedCipherList.instance.register(conf)

              @sCipher << conf
            rescue OpenSSL::Cipher::CipherError => ex
              teLogger.debug "Algo '#{c}' hit error : #{ex.message}"
            end
          end
        end

        @sCipher

      end

      def self.get_cipher(algo, keysize = nil, mode = nil)
        supported_ciphers if Ccrypto::SupportedCipherList.instance.algo_count == 0

        if is_empty?(algo)
          []
        elsif is_empty?(keysize) and is_empty?(mode)
          teLogger.debug "get_cipher algo #{algo} only"
          Ccrypto::SupportedCipherList.instance.find_algo(algo)
        elsif is_empty?(mode) and not_empty?(keysize)
          teLogger.debug "get_cipher algo #{algo} keysize #{keysize}"
          Ccrypto::SupportedCipherList.instance.find_algo_keysize(algo, keysize)
        elsif not_empty?(mode) and is_empty?(keysize)
          teLogger.debug "get_cipher algo #{algo} mode #{mode}"
          Ccrypto::SupportedCipherList.instance.find_algo_mode(algo, mode)
        elsif not_empty?(keysize) and not_empty?(mode)
          teLogger.debug "get_cipher #{algo}/#{keysize}/#{mode}"
          Ccrypto::SupportedCipherList.instance.find_algo_keysize_mode(algo, keysize, mode)
        end
      end
      class << self
        alias_method :get_cipher_config, :get_cipher
      end

      def self.supported_cipher_list
        if Ccrypto::SupportedCipherList.instance.algo_count == 0
          []
        else
          Ccrypto::SupportedCipherList.instance
        end
      end

      def self.is_supported_cipher?(c)
        case c
        when String
          supported_ciphers if @sCipherStr.nil?

          if not @sCipherStr.nil?
            @sCipherStr.include?(C)
          else
            false
          end
        when Ccrypto::CipherConfig
          @sCipher.include?(c)
        else
          raise Ccrypto::CipherEngineException, "Unsupported input #{c} to check supported cipher"
        end
      end

      def self.to_openssl_spec(spec)

        case spec
        when Ccrypto::CipherConfig
          spec.native_config[:algo_str]
          #@sCipher[spec]
        else
          raise Ccrypto::Error, "Unknown spec #{spec.inspect}"
        end

      end # self.to_openssl_spec(spec)

      def initialize(*args, &block)

        @spec = args.first

        raise Ccrypto::CipherEngineException, "Not supported cipher spec #{@spec.class}" if not @spec.is_a?(Ccrypto::CipherConfig)

        teLogger.debug "Cipher spec : #{@spec} (Native algo : #{@spec.native_config[:algo_str]})"

        @cipher = OpenSSL::Cipher.new(@spec.native_config[:algo_str])

        case @spec.cipherOps
        when :encrypt, :enc
          teLogger.debug "Operation encrypt"
          @cipher.encrypt
        when :decrypt, :dec
          teLogger.debug "Operation decrypt"
          @cipher.decrypt
        else
          raise Ccrypto::CipherEngineException, "Cipher operation (encrypt/decrypt) must be given"
        end


        if @spec.has_iv?
          teLogger.debug "IV from spec"
          @cipher.iv = @spec.iv
          teLogger.debug "IV : #{to_hex(@spec.iv)} / #{@spec.iv.length}"
        else
          teLogger.debug "Generate random IV"
          @spec.iv = @cipher.random_iv
          teLogger.debug "IV : #{to_hex(@spec.iv)} / #{@spec.iv.length}"
        end


        if @spec.has_key?
          teLogger.debug "Key from spec"
          case @spec.key
          when Ccrypto::SecretKey
            @cipher.key = @spec.key.to_bin
          when String
            @cipher.key = @spec.key
          else
            raise Ccrypto::CipherEngineException, "Unknown key type for processing #{@spec.key}"
          end
        else
          teLogger.debug "Generate random Key"
          @spec.key = @cipher.random_key
        end


        if @spec.is_mode?(:ccm)
          #if not_empty?(@spec.auth_data)
            if @spec.is_encrypt_cipher_mode?
              teLogger.debug "Setting ccm plaintext data length (ccm mode) [#{@spec.plaintext_length}]"
              @cipher.ccm_data_len = @spec.plaintext_length
              teLogger.debug "Setting auth data (ccm mode)"
              @cipher.auth_data = @spec.auth_data.nil? ? "" : @spec.auth_data
              teLogger.debug "Setting auth tag len (ccm mode)"
              @cipher.auth_tag_len = 12
            elsif @spec.is_decrypt_cipher_mode?
              teLogger.debug "Setting ccm cipher data length (ccm mode) #{@spec.ciphertext_length}"
              @cipher.ccm_data_len = @spec.ciphertext_length
              teLogger.debug "Setting auth data (ccm mode)"
              @cipher.auth_data = @spec.auth_data.nil? ? "" : @spec.auth_data
              teLogger.debug "Setting auth tag (ccm mode)"
              @cipher.auth_tag = @spec.auth_tag
            end
          #end


        elsif @spec.is_auth_mode_cipher?

          if not_empty?(@spec.auth_data) and not ((@spec.is_mode?("cbc-hmac-sha1") or @spec.is_mode?("cbc-hmac-sha256")))
            teLogger.debug "Setting auth data (generic mode)"
            @cipher.auth_data = @spec.auth_data

            if @spec.is_decrypt_cipher_mode?
              teLogger.debug "Setting auth tag (generic mode)"
              raise CipherEngineException, "Tag length of 16 bytes is expected" if @spec.auth_tag.bytesize != 16 and @spec.is_mode?(:gcm)
              @cipher.auth_tag = @spec.auth_tag
            end
          end

        end


      end # initialize 

      def update(val)
        if not_empty?(val)
          res = @cipher.update(val) 
          teLogger.debug "(update) Written #{val.length} bytes"
          res
        end
      end

      def final(val = nil)
        res = []

        begin

          if not_empty?(val)
            teLogger.debug "(final) Written #{val.length} bytes"
            res << @cipher.update(val) 
          end

          res << @cipher.final
          teLogger.debug "(final) cipher finalized"

        rescue Exception => ex
          teLogger.error self
          teLogger.error ex.backtrace.join("\n")
          raise CipherEngineException, ex
        end

        #if @spec.is_mode?(:gcm)
        if @spec.is_auth_mode_cipher? and @spec.is_encrypt_cipher_mode?
          @spec.auth_tag = @cipher.auth_tag
        end

        res.join
      end

      def reset
        @cipher.reset
      end

      def method_missing(mtd, *args, &block)
        if not @cipher.nil?
          @cipher.send(mtd, *args, &block)
        else
          super
        end
      end

    end
  end
end
