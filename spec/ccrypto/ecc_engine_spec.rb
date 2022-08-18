

RSpec.describe "ECC Engine Spec" do

  it 'generates ECC keypair based on returned value' do

    require 'ccrypto/ruby'

    ecc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig)
    expect(ecc != nil).to be true

    ecc.supported_curves.each do |c|
      puts "Generating ECC algo #{c}"
      kp = Ccrypto::AlgoFactory.engine(c).generate_keypair
      expect(kp != nil).to be true
      expect(kp.is_a?(Ccrypto::KeyBundle)).to be true
    end

  end


  it 'generates ECC keypair based on user input' do
    require 'ccrypto/ruby'

    kpf = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig.new("secp256k1"))
    kp = kpf.generate_keypair
    expect(kp != nil).to be true
    expect(kp.is_a?(Ccrypto::KeyBundle)).to be true

  end

  it 'store to PEM format' do
    
    kpf = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig.new("secp256k1"))
    kp = kpf.generate_keypair
    expect(kp != nil).to be true
    expect(kp.is_a?(Ccrypto::KeyBundle)).to be true

    # no password
    pem = kp.to_storage(:pem)
    expect(pem != nil).to be true

    kpfc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCKeyBundle)
    rkp = kpfc.from_storage(pem)
    expect(rkp != nil).to be true
    expect(rkp.equal?(kp)).to be true

    # with password
    spem = kp.to_storage(:pem) do |key|
      case key
      when :store_cipher
        # default is AES-256-GCM
        "AES-256-CBC"
      when :store_pass
        "p@ssw0rd"
      end
    end
    expect(spem != nil).to be true


    kpfc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCKeyBundle)
    expect {
      # no password (block) is given
      rkp = kpfc.from_storage(spem) 
    }.to raise_exception(Ccrypto::KeyBundleStorageException)

    rkp2 = kpfc.from_storage(spem) do |key|
      case key
      when :store_pass
        "p@ssw0rd"
      end
    end
    expect(rkp2.equal?(kp)).to be true

    # password is wrong
    expect {
      rkp = kpfc.from_storage(spem) do |key|
        case key
        when :store_pass
          "asdf"
        end
      end
    }.to raise_exception(Ccrypto::KeyBundleStorageException)

  end

  # this test case is done ine X509 engine
  #it 'store to P12 format' do
  #  
  #end


  it 'sign data with ECC keypair' do

    conf = Ccrypto::ECCConfig.new("secp256k1")
    kpf = Ccrypto::AlgoFactory.engine(conf)
    kp = kpf.generate_keypair

    conf.keypair = kp
    data_to_be_signed = "testing 123" * 128
    res = kpf.sign(data_to_be_signed)
    expect(res).not_to be nil

    vres = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig).verify(kp.public_key, data_to_be_signed, res)
    expect(vres).to be true
    
  end

  it 'derives two different session key' do
    
    c = Ccrypto::ECCConfig.new("secp256k1")
    eng = Ccrypto::AlgoFactory.engine(c)

    k1 = eng.generate_keypair
    k2 = eng.generate_keypair

    expect(k1.equal?(k2)).to be false

    pubK1 = k1.nativeKeypair.public_key
    pubK2 = k2.nativeKeypair.public_key

    privK1 = k1.nativeKeypair.private_key
    s1 = k1.nativeKeypair.dh_compute_key(pubK1)
    s2 = k1.nativeKeypair.dh_compute_key(pubK2)

    s3 = k2.nativeKeypair.dh_compute_key(pubK1)
    s4 = k2.nativeKeypair.dh_compute_key(pubK2)

    expect(s2 == s3).to be true
    expect(s1 != s4).to be true

  end

end
