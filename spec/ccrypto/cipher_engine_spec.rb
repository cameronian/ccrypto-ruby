

RSpec.describe "Cipher engine spec for Ruby" do

  #it 'encrypt and decrypt' do

  #  require 'ccrypto/ruby'

  #  cipher = Ccrypto::AlgoFactory.engine(Ccrypto::CipherConfig)
  #  expect(cipher).not_to be nil

  #  cipher.supported_ciphers.each do |c|
  #    
  #    next if (c =~ /wrap/) or (c =~ /xts/)

  #    spec = Ccrypto::DirectCipherConfig.new(c)
  #    spec.cipherOps = :encrypt

  #    cc = Ccrypto::AlgoFactory.engine(spec)
  #    expect(cc).not_to be nil

  #    # generate random data
  #    sr = Ccrypto::AlgoFactory.engine(Ccrypto::SecureRandomConfig)
  #    data = sr.random_hex(32)

  #    # xts mode failed here
  #    res = cc.update(data) + cc.final

  #    # decryption here
  #    spec.cipherOps = :decrypt
  #    ccd = Ccrypto::AlgoFactory.engine(spec)

  #    if (c.downcase =~ /ccm/) == nil
  #      if not (spec.is_gcm_mode? and spec.is_ocb_mode?)
  #        dec = ccd.update(res)
  #      else
  #        dec = ccd.update(res) + ccd.final
  #      end

  #      expect(dec == data).to be true
  #    end

  #  end

  # expect {
  #   Ccrypto::AlgoFactory.engine(Ccrypto::DirectCipherConfig.new("twofish-128-cbc")) 
  # }.to raise_exception(Ccrypto::CipherEngineException)
  #  
  #end

  it 'encrypt and decrypt using user input' do
   
    require 'ccrypto/ruby'

    testkey = [
      Ccrypto::DirectCipherConfig.new({ algo: :aes, keysize: 128, mode: :cbc, padding: :pkcs5 }),
      Ccrypto::DirectCipherConfig.new({ algo: :aes, keysize: 256, mode: :gcm, padding: :pkcs5, auth_data: "Header data for gcm" }),
     
      Ccrypto::DirectCipherConfig.new({ algo: :chacha20, keysize: 256, mode: :poly1305 }),

      Ccrypto::DirectCipherConfig.new({ algo: :camellia, keysize: 256, mode: :cbc, padding: :pkcs5 }),
      Ccrypto::DirectCipherConfig.new({ algo: :camellia, keysize: 256, mode: :ctr, padding: :pkcs5 }),

      Ccrypto::DirectCipherConfig.new({ algo: :aria, keysize: 256, mode: :cbc, padding: :pkcs5 }),
      Ccrypto::DirectCipherConfig.new({ algo: :aria, keysize: 256, mode: :ctr, padding: :pkcs5 }),
      Ccrypto::DirectCipherConfig.new({ algo: :aria, keysize: 256, mode: :gcm, padding: :pkcs5 }),

      Ccrypto::DirectCipherConfig.new({ algo: :seed, keysize: 256, mode: :cbc, padding: :pkcs5 }),
      Ccrypto::DirectCipherConfig.new({ algo: :seed, keysize: 256, mode: :ofb, padding: :pkcs5 }),

      Ccrypto::DirectCipherConfig.new({ algo: :sm4, keysize: 128, mode: :cbc, padding: :pkcs5 }),
      Ccrypto::DirectCipherConfig.new({ algo: :sm4, keysize: 128, mode: :ctr, padding: :pkcs5 }),
      
      Ccrypto::DirectCipherConfig.new({ algo: :blowfish, keysize: 128, mode: :cfb, padding: :pkcs5 }),

    ]

    testkey.each do |hc|
      spec = hc.clone
      spec.cipherOps = :encrypt

      cc = Ccrypto::AlgoFactory.engine(spec)
      expect(cc).not_to be nil

      data = "password"

      enc = cc.final(data)

      spec.cipherOps = :decrypt
      ccd = Ccrypto::AlgoFactory.engine(spec)

      dec = ccd.final(enc)

      expect(dec == data).to be true
      
    end

  end

  it 'encrypt and decrypt with AES GCM auth data' do

    cc = Ccrypto::DirectCipherConfig.new({ algo: :aes, keysize: 256, mode: :gcm })
    cc.auth_data = "this is external auth data"

    cc.encrypt_cipher_mode

    conv = Ccrypto::UtilFactory.instance(:converter)

    enc = []
    data = ["first par tof the data", " second part of the data is fun"]
    c = Ccrypto::AlgoFactory.engine(cc)
    enc << c.update(data[0])
    enc << c.final(data[1])

    puts "Encryption done #{conv.to_hex(enc.join).length}"

    plain = []
    cc.decrypt_cipher_mode
    d = Ccrypto::AlgoFactory.engine(cc)
    plain << d.update(enc.join)
    plain << d.final

    expect(plain.join == data.join).to be true

  end


end
