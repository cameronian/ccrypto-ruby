

RSpec.describe "Test OpenSSL 3 upgrade" do

  it 'creates ECC key, store to file system and load back' do
  
    if OpenSSL::VERSION > "3.0.0"

      ec = OpenSSL::PKey::EC.generate("prime256v1")
      data = "data for signing"
      sign = ec.dsa_sign_asn1(data)

      pubBin = ec.public_to_der

      pubKey = OpenSSL::PKey::EC.new(pubBin)

      expect(pubKey.verify_raw(nil, sign, data)).to be true
      expect(pubKey.dsa_verify_asn1(data, sign)).to be true

    end

  end

end
