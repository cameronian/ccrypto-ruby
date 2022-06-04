

RSpec.describe "RSA Engine Spec" do

  it 'generates RSA keypair based on user input' do
    require 'ccrypto/ruby'

    kpf = Ccrypto::AlgoFactory.engine(Ccrypto::RSAConfig.new(2048))
    kp = kpf.generate_keypair
    expect(kp != nil).to be true
    expect(kp.is_a?(Ccrypto::KeyBundle)).to be true

  end

  it 'store to PEM format' do
    
    kpf = Ccrypto::AlgoFactory.engine(Ccrypto::RSAConfig.new(2048))
    kp = kpf.generate_keypair
    expect(kp != nil).to be true
    expect(kp.is_a?(Ccrypto::KeyBundle)).to be true

    # no password
    pem = kp.to_storage(:pem)
    expect(pem != nil).to be true

    kpfc = Ccrypto::AlgoFactory.engine(Ccrypto::RSAKeyBundle)
    rkp = kpfc.from_storage(pem)
    expect(rkp != nil).to be true
    expect(rkp.equal?(kp)).to be true

    # with password
    spem = kp.to_storage(:pem) do |key|
      case key
      when :pem_cipher
        # default is AES-256-GCM
        "AES-256-CBC"
      when :pem_pass
        "p@ssw0rd"
      end
    end
    expect(spem != nil).to be true


    kpfc = Ccrypto::AlgoFactory.engine(Ccrypto::RSAKeyBundle)
    expect {
      # no password (block) is given
      rkp = kpfc.from_storage(spem) 
    }.to raise_exception(Ccrypto::KeyBundleStorageException)

    rkp2 = kpfc.from_storage(spem) do |key|
      case key
      when :pem_pass
        "p@ssw0rd"
      end
    end
    expect(rkp2.equal?(kp)).to be true

    # password is wrong
    expect {
      rkp = kpfc.from_storage(spem) do |key|
        case key
        when :pem_pass
          ""
        end
      end
    }.to raise_exception(Ccrypto::KeyBundleStorageException)

  end

  it 'sign & verify data with RSA keypair' do

    conf = Ccrypto::RSAConfig.new(2048)
    kpf = Ccrypto::AlgoFactory.engine(conf)
    kp = kpf.generate_keypair

    conf.private_key = kp.private_key
    data_to_be_signed = "testing 123" * 128
    res = kpf.sign(data_to_be_signed)
    expect(res).not_to be nil

    expect {
      kpf.sign(data_to_be_signed) do |k|
        case k
        when :sign_hash
          "unknown"
        end
      end
    }.to raise_exception(Ccrypto::KeypairEngineException)

    vres = Ccrypto::AlgoFactory.engine(Ccrypto::RSAConfig).verify(kp.public_key, data_to_be_signed, res)
    expect(vres).to be true

    expect(Ccrypto::AlgoFactory.engine(Ccrypto::RSAConfig).verify(kp.public_key, data_to_be_signed, res) do |k|
      case k
      when :pss_mode
        true
      end
    end).to be false

    res2 = kpf.sign(data_to_be_signed) do |k|
      case k
      when :pss_mode
        true
      end
    end
    expect(res2).not_to be nil

    vres2 = Ccrypto::AlgoFactory.engine(Ccrypto::RSAConfig).verify(kp.public_key, data_to_be_signed, res2) do |k|
      case k
      when :pss_mode
        true
      end
    end
    expect(vres2).to be true
    
  end

  it 'encrypt & decrypt data with RSA keypair, default OAEP mode' do

    conf = Ccrypto::RSAConfig.new(2048)
    kpf = Ccrypto::AlgoFactory.engine(conf)
    kp = kpf.generate_keypair

    conf.private_key = kp.private_key

    # this is the max for oaep padding or it will hit data too large for keysize error
    # 8 * 26 = 208 + 6 = 214 bytes == 1712 bits. 
    # 2048 bits key size means 336 bits/42 bytes is for padding
    data_to_be_encrypted = ("testing " * 26)
    data_to_be_encrypted = "#{data_to_be_encrypted}123456"

    sRsaEng = Ccrypto::AlgoFactory.engine(Ccrypto::RSAConfig)
    enc = sRsaEng.encrypt(kp.public_key, data_to_be_encrypted)
    expect(enc).not_to be nil

    plain = kpf.decrypt(enc)
    expect(plain).not_to be nil
    expect(plain == data_to_be_encrypted).to be true

    data_to_be_encrypted = "testing "
    enclc = sRsaEng.encrypt(kp.public_key, data_to_be_encrypted)
    puts "Input 8 bytes, OAEP output length : #{enclc.length} bytes"
    p enclc

    # pkcs1 padding
    # max input size = 240 + 5 = 245 bytes === 1960 bits
    # padding is 11 bytes
    data_to_be_encrypted = "testing "*30
    data_to_be_encrypted = "#{data_to_be_encrypted}12345"
    enc2 = sRsaEng.encrypt(kp.public_key, data_to_be_encrypted) do |k|
      case k
      when :padding
        :pkcs1
      end
    end
    expect(enc2).not_to be nil

    plain2 = kpf.decrypt(enc2) do |k|
      case k
      when :padding
        :pkcs1
      end
    end
    expect(plain2).not_to be nil
    expect(plain2 == data_to_be_encrypted).to be true

    data_to_be_encrypted = "testing "
    enclc1 = sRsaEng.encrypt(kp.public_key, data_to_be_encrypted)
    puts "Input 8 bytes, pkcs1 padding output length : #{enclc1.length} bytes"
    p enclc1


    # no padding
    # Full key size 2048 bits == 256 bytes = 8*32 bytes
    data_to_be_encrypted = "testing "*32
    enc3 = sRsaEng.encrypt(kp.public_key, data_to_be_encrypted) do |k|
      case k
      when :padding
        :no_padding
      end
    end
    expect(enc3).not_to be nil

    plain3 = kpf.decrypt(enc3) do |k|
      case k
      when :padding
        :no_padding
      end
    end
    expect(plain3).not_to be nil
    expect(plain3 == data_to_be_encrypted).to be true

    data_to_be_encrypted = "testing "
    enclc3 = sRsaEng.encrypt(kp.public_key, data_to_be_encrypted)
    puts "Input 8 bytes, no padding output length : #{enclc3.length} bytes"
    p enclc3

  end


end
