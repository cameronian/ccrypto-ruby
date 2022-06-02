

module Ccrypto
  module Ruby
    module PEMStore
      include TR::CondUtils
      include DataConversion

      class PEMStoreException < KeyBundleStorageException; end

      module ClassMethods
        def is_pem?(input)
          if is_empty?(input)
            false
          else
            begin
              (input =~ /BEGIN/) != nil
            rescue ArgumentError => ex
              if ex.message =~ /invalid byte sequence/
                false
              else
                raise KeypairEngineException, ex
              end
            end
          end
        end

        def from_pem(input, &block)

          begin
            # try with no password first to check if the keystore is really encrypted
            # If not the library will prompt at command prompt which might halt the flow of program
            pKey = OpenSSL::PKey.read(input,"")
            ECCKeyBundle.new(pKey)
          rescue OpenSSL::PKey::PKeyError => ex
            raise PEMStoreException, "block is required" if not block
            pass = block.call(:pem_pass)
            begin
              pKey = OpenSSL::PKey.read(input, pass)
              ECCKeyBundle.new(pKey)
            rescue OpenSSL::PKey::PKeyError => exx
              raise PEMStoreException, exx
            end
          end

        end
      end
      def self.included(klass)
        klass.extend(ClassMethods)
      end

      def to_pem(&block)
        raise PEMStoreException, "Block is required" if not block
        kcipher = block.call(:pem_cipher) 
        kpass = block.call(:pem_pass)

        kcipher = "AES-256-GCM" if is_empty?(kcipher)

        keypair = block.call(:keypair)
        raise PEMStoreException, "Keypair is required" if is_empty?(keypair)

        if not_empty?(kpass)
          kCipher = OpenSSL::Cipher.new(kcipher)
          keypair.export(kCipher, kpass)
        else
          keypair.export
        end

      end
      
    end
  end
end
