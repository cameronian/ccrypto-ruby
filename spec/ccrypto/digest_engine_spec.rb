

RSpec.describe "Digest Engine for Ruby" do

  it 'generates digest from supported list' do
   
    require 'ccrypto/ruby'

    s2 = Ccrypto::AlgoFactory.engine(Ccrypto::DigestConfig)
    expect(s2).not_to be nil

    s2.supported.each do |d|
      puts "Testing algo #{d.provider_config}"

      de = Ccrypto::AlgoFactory.engine(d)
      expect(de).not_to be nil

      res = de.digest("password")
      expect(res.length == d.outBitLength/8).to be true

      de.reset

      de.digest_update("pass")
      de.digest_update("word")
      res2 = de.digest_final
      expect(res2 == res).to be true

      hres = de.digest("password", :hex)
      de.reset
      de.digest_update("pass")
      de.digest_update("word")
      hres2 = de.digest_final(:hex)
      expect(hres2 == hres).to be true

      de.reset
      bres = de.digest("password",:b64)
      de.reset
      de.digest_update("pas")
      de.digest_update("sword")
      bres2 = de.digest_final(:b64)
      expect(bres2 == bres).to be true
    end

    expect { Ccrypto::AlgoFactory.engine(Ccrypto::HARAKA256) }.to raise_exception(Ccrypto::DigestEngineException)

  end

  it 'generates digest from user input' do
    
    de = Ccrypto::AlgoFactory.engine(Ccrypto::DigestConfig)
    expect(de).not_to be nil

    dde = de.digest(:sha256)
    data1 = "Testing"
    data2 = "12345667"

    dde.digest_update(data1)
    dde.digest_update(data2)
    res = dde.digest_final

    expect(res).not_to be nil

    hres = dde.digest_final(:hex)
    expect(hres == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to be true

  end

end
