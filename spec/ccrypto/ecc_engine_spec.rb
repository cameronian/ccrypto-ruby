

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

end
