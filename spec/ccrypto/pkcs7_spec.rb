

RSpec.describe "Test PKCS7" do

  #before do
  #
  #  ecc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig.new)
  #  @kp = ecc.generate_keypair

  #  prof = Ccrypto::X509::CertProfile.new

  #  prof.owner_name = "Simmon"
  #  prof.org = "Agent"

  #  prof.org_unit = ["Sara","id=A119"]
  #  prof.dns_name = "https://agent.com"
  #  prof.email = "simmon@agent.com"

  #  prof.key_usage.enable_digitalSignature.enable_nonRepudiation

  #  prof.ext_key_usage.enable_serverAuth.enable_clientAuth.enable_timestamping

  #  prof.gen_subj_key_id = true
  #  prof.gen_auth_key_id = true
  #  prof.public_key = @kp.public_key

  #  fact = Ccrypto::AlgoFactory.engine(prof)
  #  @cert = fact.generate(@kp)

  #end

  it 'sign and verify default attached signature' do
    
    ecc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig.new)
    kp = ecc.generate_keypair

    prof = Ccrypto::X509::CertProfile.new

    prof.owner_name = "Simmon"
    prof.org = "Agent"

    prof.org_unit = ["Sara","id=A119"]
    prof.dns_name = "https://agent.com"
    prof.email = "simmon@agent.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation

    prof.ext_key_usage.enable_serverAuth.enable_clientAuth.enable_timestamping

    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true
    prof.public_key = kp.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    cert = fact.generate(kp)

   
    conf = Ccrypto::PKCS7Config.new
    conf.keybundle = kp
    conf.signerCert = cert

    p7 = Ccrypto::AlgoFactory.engine(conf)
    expect(p7).not_to be nil

    data = "testging 18181818"*120
    res = p7.sign(data) 
    expect(res).not_to be nil

    vp7 = Ccrypto::AlgoFactory.engine(Ccrypto::PKCS7Config.new)
    vres = vp7.verify(res) do |k,v|
      case k
      when :verify_certificate
        true
      when :attached_data
        expect(v == data).to be true
      end
    end
    expect(vres).to be true

  end

  it 'sign and verify detached signature' do
    
    ecc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig.new)
    kp = ecc.generate_keypair

    prof = Ccrypto::X509::CertProfile.new

    prof.owner_name = "Simmon"
    prof.org = "Agent"

    prof.org_unit = ["Sara","id=A119"]
    prof.dns_name = "https://agent.com"
    prof.email = "simmon@agent.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation

    prof.ext_key_usage.enable_serverAuth.enable_clientAuth.enable_timestamping

    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true
    prof.public_key = kp.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    cert = fact.generate(kp)


    conf = Ccrypto::PKCS7Config.new
    conf.keybundle = kp
    conf.signerCert = cert

    p7 = Ccrypto::AlgoFactory.engine(conf)
    expect(p7).not_to be nil

    data = "testging 28282828"*128
    res = p7.sign(data) do |k,v|
      case k
      when :detached_sign
        true
      end
    end
    expect(res).not_to be nil

    vp7 = Ccrypto::AlgoFactory.engine(Ccrypto::PKCS7Config.new)
    # scenario 1: Application accepted cert, data correct
    vres = vp7.verify(res) do |k,v|
      case k
      when :verify_certificate
        true
      when :signed_data
        data
      end
    end
    expect(vres).to be true

    # scenario 2: Application accepted cert, data wrong
    vres2 = vp7.verify(res) do |k,v|
      case k
      when :verify_certificate
        true
      when :signed_data
        "obviously wrong data"
      end
    end
    expect(vres2).to be false

    # scenario 3: Application rejected cert. Data not needed
    vres3 = vp7.verify(res) do |k,v|
      case k
      when :verify_certificate
        false
      end
    end
    expect(vres3).to be false

    # scenario 4: Application no checking on cert. Data correct.
    vres4 = vp7.verify(res) do |k,v|
      case k
      when :signed_data
        data
      end
    end
    expect(vres4).to be true

    # scenario 5: Application no checking on cert. Data garbage.
    vres5 = vp7.verify(res) do |k,v|
      case k
      when :signed_data
        "whatever you say"
      end
    end
    expect(vres5).to be false

  end

  it 'encrypt and decrypt PKCS7 envelope with RSA keypair' do
  
    # PKCS7 of OpenSSL only support RSA keypair and not ECC keypair
    rsa = Ccrypto::AlgoFactory.engine(Ccrypto::RSAConfig.new(2048))
    kp = rsa.generate_keypair

    prof = Ccrypto::X509::CertProfile.new

    prof.owner_name = "Simmon RSA"
    prof.org = "Agent"

    prof.org_unit = ["Sara","id=A119"]
    prof.dns_name = "https://agent.com"
    prof.email = "simmon@agent.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation

    prof.ext_key_usage.enable_serverAuth.enable_clientAuth.enable_timestamping

    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true
    prof.public_key = kp.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    cert = fact.generate(kp)

    conf = Ccrypto::PKCS7Config.new
    conf.add_recipient_cert(cert)

    p7 = Ccrypto::AlgoFactory.engine(conf)
    expect(p7).not_to be nil 

    data = "testing "*102400
    enc = p7.encrypt(data)
    expect(enc).not_to be nil

    dconf = Ccrypto::PKCS7Config.new
    dconf.keybundle = kp
    dconf.certForDecryption = cert
    dp7 = Ccrypto::AlgoFactory.engine(dconf)
    dec = dp7.decrypt(enc)
    expect(dec).not_to be nil
    expect(dec == data).to be true

    # On Ruby-3.0.2
    # AES-256-CTR : error setting cipher
    # AES-256-OCB : error setting cipher
    # BF-CFB      : error setting cipher
    # BF-OFB      : error setting cipher
    # CHACHA20-POLY1305 : error setting cipher
    # AES-256-GCM : malloc failure
    # AES-256-CCM : malloc failure
    # AES-256-XTS : malloc failure
    ["AES-256-CBC","AES-256-CFB","AES-256-OFB","ARIA-256-CBC", "ARIA-256-CFB","ARIA-256-OFB", "BF-CBC", "CAMELLIA-256-CBC", "CAMELLIA-256-CFB", "CAMELLIA-256-OFB", "SEED-CBC", "SEED-CFB", "SEED-OFB", "SM4-CBC", "SM4-CFB", "SM4-OFB"].each do |c|

      enc2 = p7.encrypt(data) do |k|
        case k
        when :cipher
          c
        end
      end

      dec2 = dp7.decrypt(enc2)
      expect(dec2).not_to be nil
      expect(dec2 == data).to be true

    end

  end

end
