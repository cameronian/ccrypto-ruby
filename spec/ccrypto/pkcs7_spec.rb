

RSpec.describe "Test PKCS7" do

  before do
  
    ecc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig.new)
    @kp = ecc.generate_keypair

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
    prof.public_key = @kp.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    @cert = fact.generate(@kp)

  end

  it 'sign and verify default attached signature' do
   
    conf = Ccrypto::PKCS7Config.new
    conf.keybundle = @kp
    conf.x509_cert = @cert

    p7 = Ccrypto::AlgoFactory.engine(conf)
    expect(p7).not_to be nil

    data = "testging 18181818"*120
    res = p7.sign(data) 
    expect(res).not_to be nil

    vres = p7.verify(res) do |k,v|
      case k
      when :verify_certificate
        p v
        true
      when :attached_data
        expect(v == data).to be true
      end
    end
    expect(vres).to be true

  end

  it 'sign and verify detached signature' do

    conf = Ccrypto::PKCS7Config.new
    conf.keybundle = @kp
    conf.x509_cert = @cert

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

    vres = p7.verify(res) do |k,v|
      case k
      when :verify_certificate
        p v
        true
      when :sign_data
        data
      end
    end
    expect(vres).to be true

    vres2 = p7.verify(res) do |k,v|
      case k
      when :verify_certificate
        p v
        true
      when :sign_data
        "obviously wrong data"
      end
    end
    expect(vres2).to be false

    vres3 = p7.verify(res) do |k,v|
      case k
      when :verify_certificate
        false
      end
    end
    expect(vres2).to be false

    
  end

end
