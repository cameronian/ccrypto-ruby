


RSpec.describe "X509 engine spec for Ruby" do

  it 'generates X.509 certificate for ECC keypair' do
    require 'ccrypto/ruby'

    ecc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig.new)
    kp = ecc.generate_keypair

    prof = Ccrypto::X509::CertProfile.new
    expect(prof).not_to be nil

    prof.owner_name = "Jamma"
    prof.org = "SAA"

    prof.org_unit = ["asdf","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "jamma@saa.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation

    prof.ext_key_usage.enable_serverAuth.enable_clientAuth.enable_timeStamping

    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true
    prof.public_key = kp.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    c = fact.generate(kp.private_key)
    expect(c).not_to be nil
    expect(c.is_a?(Ccrypto::X509Cert)).to be true

    File.open("test.crt","wb") do |f|
      f.write c.to_der
    end

  end

  it 'generates X.509 certificate with AIA/CRL Dist Point for ECC keypair' do
    require 'ccrypto/ruby'

    ecc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig.new)
    kp = ecc.generate_keypair

    prof = Ccrypto::X509::CertProfile.new
    expect(prof).not_to be nil

    prof.owner_name = "Jamma"
    prof.org = "SAA"

    prof.org_unit = ["asdf","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "jamma@saa.com"

    #prof.key_usage.enable_digitalSignature(true) #.enable_nonRepudiation
    prof.key_usage.enable_digitalSignature(true).enable_dataEncipherment

    prof.ext_key_usage.enable_serverAuth.enable_clientAuth.enable_timeStamping

    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true
    prof.public_key = kp.public_key

    prof.crl_dist_point = ["https://www.test.com/crl", "https://www.test2.com/crl"]
    prof.ocsp_url = ["https://www.test.com/ocsp1","https://www.test2.com/ocsp2"] 
    prof.issuer_url = ["https://www.test.com/issuer/issuerx","https://www.test2.com/issuerx"]

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    c = fact.generate(kp.private_key)
    expect(c).not_to be nil
    expect(c.is_a?(Ccrypto::X509Cert)).to be true

    File.open("test_aia.crt","wb") do |f|
      f.write c.to_der
    end

  end

  it 'generates X.509 certificate with custom ext key usage for ECC keypair' do
    require 'ccrypto/ruby'

    ecc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig.new)
    kp = ecc.generate_keypair

    prof = Ccrypto::X509::CertProfile.new
    expect(prof).not_to be nil

    prof.owner_name = "Jamma"
    prof.org = "SAA"

    prof.org_unit = ["asdf","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "jamma@saa.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation

    prof.ext_key_usage.enable_serverAuth.enable_clientAuth.enable_timeStamping

    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true
    prof.public_key = kp.public_key

    prof.crl_dist_point = ["https://www.test.com/crl", "https://www.test2.com/crl"]
    prof.ocsp_url = ["https://www.test.com/ocsp1","https://www.test2.com/ocsp2"] 
    prof.issuer_url = ["https://www.test.com/issuer/issuerx","https://www.test2.com/issuerx"]

    prof.add_domain_key_usage("1.2.11.22.33")

    prof.add_custom_extension("1.24.23.44.223","For private use")

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    c = fact.generate(kp.private_key)
    expect(c).not_to be nil
    expect(c.is_a?(Ccrypto::X509Cert)).to be true

    File.open("test_custom_eku.crt","wb") do |f|
      f.write c.to_der
    end

  end

  it 'generates X.509 certificate for RSA keypair' do
    require 'ccrypto/ruby'

    rsa = Ccrypto::AlgoFactory.engine(Ccrypto::RSAConfig.new(2048))
    kp = rsa.generate_keypair

    prof = Ccrypto::X509::CertProfile.new
    expect(prof).not_to be nil

    prof.owner_name = "Jamma"
    prof.org = "SAA"

    prof.org_unit = ["asdf","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "jamma@saa.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation

    prof.ext_key_usage.enable_serverAuth.enable_clientAuth.enable_timeStamping

    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true
    prof.public_key = kp.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    c = fact.generate(kp)
    expect(c).not_to be nil
    expect(c.is_a?(Ccrypto::X509Cert)).to be true

    File.open("test-rsa.crt","wb") do |f|
      f.write c.to_der
    end

  end

  it 'generates ECC, X.509 certificates with new cert date before or after issuer date' do
    require 'ccrypto/ruby'

    ecc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig.new)
    root = ecc.generate_keypair

    prof = Ccrypto::X509::CertProfile.new
    prof.owner_name = "Root CA"
    prof.org = "Cameron"

    prof.org_unit = ["Solutioning","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "Root.CA@cameronion.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation.enable_keyCertSign.enable_crlSign
    prof.ext_key_usage.enable_serverAuth.enable_clientAuth

    prof.gen_issuer_cert = true
    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true
    prof.public_key = root.public_key

    prof.not_before = Time.now.last_week
    prof.validity(2,:years)

    fact = Ccrypto::AlgoFactory.engine(prof)
    rootCert = fact.generate(root)


    subCA = ecc.generate_keypair

    prof = Ccrypto::X509::CertProfile.new
    prof.owner_name = "Sub CA"
    prof.org = "Cameron"

    prof.org_unit = ["Solutioning","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "Sub.CA@cameronion.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation.enable_keyCertSign.enable_crlSign
    prof.ext_key_usage.enable_serverAuth.enable_clientAuth

    prof.gen_issuer_cert = true
    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true

    prof.issuer_cert = rootCert
    prof.public_key = subCA.public_key

    prof.not_before = Time.now.last_month
    prof.validity(3, :years)

    fact = Ccrypto::AlgoFactory.engine(prof)
    subCACert = fact.generate(root)

    expect(subCACert.not_before == rootCert.not_before).to be true
    expect(subCACert.not_after == rootCert.not_after).to be true

  end


  it 'generates ECC, X.509 certificates tree and store in P12 file' do
    require 'ccrypto/ruby'

    ecc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig.new)
    root = ecc.generate_keypair

    prof = Ccrypto::X509::CertProfile.new
    prof.owner_name = "Root CA"
    prof.org = "Cameron"

    prof.org_unit = ["Solutioning","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "Root.CA@cameronion.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation.enable_keyCertSign.enable_crlSign
    prof.ext_key_usage.enable_serverAuth.enable_clientAuth

    prof.gen_issuer_cert = true
    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true
    prof.public_key = root.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    rootCert = fact.generate(root)
    expect(rootCert).not_to be nil
    expect(rootCert.is_a?(Ccrypto::X509Cert)).to be true

    File.open("root.crt","wb") do |f|
      f.write rootCert.to_der
    end

    File.open("root.p12","wb") do |f|
      ksb = root.to_storage(:p12) do |key|
        case key
        when :cert
          rootCert
        when :certchain
          [rootCert]
        when :store_pass
          "password"
        when :key_name
          "Test Root CA"
        end
      end

      f.write ksb
    end

    puts "Root CA Cert Generated"

    subCA = ecc.generate_keypair

    prof = Ccrypto::X509::CertProfile.new
    prof.owner_name = "Sub CA"
    prof.org = "Cameron"

    prof.org_unit = ["Solutioning","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "Sub.CA@cameronion.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation.enable_keyCertSign.enable_crlSign
    prof.ext_key_usage.enable_serverAuth.enable_clientAuth

    prof.gen_issuer_cert = true
    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true

    prof.issuer_cert = rootCert
    prof.public_key = subCA.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    subCACert = fact.generate(root)
    expect(subCACert).not_to be nil
    expect(subCACert.is_a?(Ccrypto::X509Cert)).to be true

    File.open("sub-ca.crt","wb") do |f|
      f.write subCACert.to_der
    end

    File.open("sub-ca.p12","wb") do |f|
      ksb = subCA.to_storage(:p12) do |key|
        case key
        when :cert
          subCACert
        when :certchain
          [rootCert,subCACert]
        when :store_pass
          "password"
        when :key_name
          "Test Sub CA"
        end
      end

      f.write ksb
    end

    puts "Sub CA Certificate generated"

    leafCA = ecc.generate_keypair
    prof = Ccrypto::X509::CertProfile.new
    prof.owner_name = "Operational CA"
    prof.org = "Cameron"

    prof.org_unit = ["Solutioning","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "Ops.CA@cameronion.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation.enable_keyCertSign.enable_crlSign
    prof.ext_key_usage.enable_serverAuth.enable_clientAuth

    prof.gen_issuer_cert = true
    prof.issuer_path_len = 0 # should not be any sub CA beneath this sub CA
    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true

    prof.issuer_cert = subCACert
    prof.public_key = leafCA.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    leafCACert = fact.generate(subCA)
    expect(leafCACert).not_to be nil
    expect(leafCACert.is_a?(Ccrypto::X509Cert)).to be true

    File.open("ops-ca.crt","wb") do |f|
      f.write leafCACert.to_der
    end

    File.open("ops-ca.p12","wb") do |f|
      ksb = leafCA.to_storage(:p12) do |key|
        case key
        when :cert
          leafCACert
        when :certchain
          [rootCert,subCACert,leafCACert]
        when :store_pass
          "password"
        when :key_name
          "Test Operational CA"
        end
      end

      f.write ksb
    end

    puts "Operational CA Certificate generated"


    subscriber = ecc.generate_keypair
    prof = Ccrypto::X509::CertProfile.new
    prof.owner_name = "Subscriber"
    prof.org = "Cameron"

    prof.org_unit = ["Solutioning","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "Subscriber@cameronion.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation
    prof.ext_key_usage.enable_serverAuth.enable_clientAuth

    prof.gen_issuer_cert = false
    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true

    prof.issuer_cert = leafCACert
    prof.public_key = subscriber.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    userCert = fact.generate(leafCA)
    expect(userCert).not_to be nil
    expect(userCert.is_a?(Ccrypto::X509Cert)).to be true

    File.open("enduser.crt","wb") do |f|
      f.write userCert.to_der
    end

    File.open("enduser.p12","wb") do |f|
      ksb = subscriber.to_storage(:p12) do |key|
        case key
        when :cert
          userCert
        when :certchain
          [rootCert,subCACert,leafCACert]
        when :store_pass
          "password"
        when :key_name
          "Test End User Certificate"
        end
      end

      f.write ksb
    end

    puts "User Certificate generated"

    kpfc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCKeyBundle)
    expect {
      rkp = kpfc.from_storage(File.read("enduser.p12"))
    }.to raise_exception(Ccrypto::KeyBundleStorageException)

    rkp,rcert,rchain = kpfc.from_storage(File.read("enduser.p12")) do |key|
      case key
      when :store_pass
        "password"
      end
    end
    expect(rkp != nil).to be true
    p rkp
    p subscriber
    expect(rkp.equal?(subscriber)).to be true
    expect(rcert.equal?(userCert)).to be true

    rchain.each do |cc|
      expect((cc.equal?(rootCert) or cc.equal?(subCACert) or cc.equal?(leafCACert))).to be true
    end

  end

  it 'generates RSA, X.509 certificates tree and store in P12 file' do
    require 'ccrypto/ruby'

    ecc = Ccrypto::AlgoFactory.engine(Ccrypto::RSAConfig.new)
    root = ecc.generate_keypair

    prof = Ccrypto::X509::CertProfile.new
    prof.owner_name = "Root CA RSA"
    prof.org = "Cameron"

    prof.org_unit = ["Solutioning","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "Root.CA-RSA@cameronion.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation.enable_keyCertSign.enable_crlSign
    prof.ext_key_usage.enable_serverAuth.enable_clientAuth

    prof.gen_issuer_cert = true
    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true
    prof.public_key = root.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    rootCert = fact.generate(root)
    expect(rootCert).not_to be nil
    expect(rootCert.is_a?(Ccrypto::X509Cert)).to be true

    File.open("root-rsa.crt","wb") do |f|
      f.write rootCert.to_der
    end

    File.open("root-rsa.p12","wb") do |f|
      ksb = root.to_storage(:p12) do |key|
        case key
        when :cert
          rootCert
        when :certchain
          [rootCert]
        when :store_pass
          "password"
        when :key_name
          "Test Root CA RSA"
        end
      end

      f.write ksb
    end

    puts "Root CA RSA Cert Generated"

    subCA = ecc.generate_keypair

    prof = Ccrypto::X509::CertProfile.new
    prof.owner_name = "Sub CA RSA"
    prof.org = "Cameron"

    prof.org_unit = ["Solutioning","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "Sub.CA-RSA@cameronion.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation.enable_keyCertSign.enable_crlSign
    prof.ext_key_usage.enable_serverAuth.enable_clientAuth

    prof.gen_issuer_cert = true
    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true

    prof.issuer_cert = rootCert
    prof.public_key = subCA.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    subCACert = fact.generate(root)
    expect(subCACert).not_to be nil
    expect(subCACert.is_a?(Ccrypto::X509Cert)).to be true

    File.open("sub-ca-rsa.crt","wb") do |f|
      f.write subCACert.to_der
    end

    File.open("sub-ca-rsa.p12","wb") do |f|
      ksb = subCA.to_storage(:p12) do |key|
        case key
        when :cert
          subCACert
        when :certchain
          [rootCert,subCACert]
        when :store_pass
          "password"
        when :key_name
          "Test Sub CA RSA"
        end
      end

      f.write ksb
    end

    puts "Sub CA RSA Certificate generated"

    leafCA = ecc.generate_keypair
    prof = Ccrypto::X509::CertProfile.new
    prof.owner_name = "Operational CA RSA"
    prof.org = "Cameron"

    prof.org_unit = ["Solutioning","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "Ops.CA-RSA@cameronion.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation.enable_keyCertSign.enable_crlSign
    prof.ext_key_usage.enable_serverAuth.enable_clientAuth

    prof.gen_issuer_cert = true
    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true

    prof.issuer_cert = subCACert
    prof.public_key = leafCA.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    leafCACert = fact.generate(subCA)
    expect(leafCACert).not_to be nil
    expect(leafCACert.is_a?(Ccrypto::X509Cert)).to be true

    File.open("ops-ca-rsa.crt","wb") do |f|
      f.write leafCACert.to_der
    end

    File.open("ops-ca-rsa.p12","wb") do |f|
      ksb = leafCA.to_storage(:p12) do |key|
        case key
        when :cert
          leafCACert
        when :certchain
          [rootCert,subCACert,leafCACert]
        when :store_pass
          "password"
        when :key_name
          "Test Operational CA RSA"
        end
      end

      f.write ksb
    end

    puts "Operational CA RSA Certificate generated"


    subscriber = ecc.generate_keypair
    prof = Ccrypto::X509::CertProfile.new
    prof.owner_name = "Subscriber RSA"
    prof.org = "Cameron"

    prof.org_unit = ["Solutioning","id=jasjdf"]
    prof.dns_name = "https://asdf.com"
    prof.email = "Subscriber-RSA@cameronion.com"

    prof.key_usage.enable_digitalSignature.enable_nonRepudiation
    prof.ext_key_usage.enable_serverAuth.enable_clientAuth

    prof.gen_issuer_cert = false
    prof.gen_subj_key_id = true
    prof.gen_auth_key_id = true

    prof.issuer_cert = leafCACert
    prof.public_key = subscriber.public_key

    fact = Ccrypto::AlgoFactory.engine(prof)
    expect(fact).not_to be nil

    userCert = fact.generate(leafCA)
    expect(userCert).not_to be nil
    expect(userCert.is_a?(Ccrypto::X509Cert)).to be true

    File.open("enduser-rsa.crt","wb") do |f|
      f.write userCert.to_der
    end

    File.open("enduser-rsa.p12","wb") do |f|
      ksb = subscriber.to_storage(:p12) do |key|
        case key
        when :cert
          userCert
        when :certchain
          [rootCert,subCACert,leafCACert]
        when :store_pass
          "password"
        when :key_name
          "Test End User Certificate RSA"
        end
      end

      f.write ksb
    end

    puts "User RSA Certificate generated"

    kpfc = Ccrypto::AlgoFactory.engine(Ccrypto::ECCKeyBundle)
    expect {
      rkp = kpfc.from_storage(File.read("enduser-rsa.p12"))
    }.to raise_exception(Ccrypto::KeyBundleStorageException)

    rkp,rcert,rchain = kpfc.from_storage(File.read("enduser-rsa.p12")) do |key|
      case key
      when :store_pass
        "password"
      end
    end
    expect(rkp != nil).to be true
    p rkp
    p subscriber
    expect(rkp.equal?(subscriber)).to be true
    expect(rcert.equal?(userCert)).to be true

    rchain.each do |cc|
      expect((cc.equal?(rootCert) or cc.equal?(subCACert) or cc.equal?(leafCACert))).to be true
    end

  end


end
