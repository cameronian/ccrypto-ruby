
require 'toolrack'
include TR::CondUtils

RSpec.describe "Cipher engine spec for Ruby" do

  it 'allow user to find available algo + config' do
    c = Ccrypto::AlgoFactory.engine(Ccrypto::CipherConfig)
    aesConf = c.get_cipher("aes")
    expect(aesConf.nil?).to be false
    expect(aesConf.count > 0).to be true
    aesConf.each do |c|
      puts "Processing algo #{c.native_config[:algo_str]}"
      expect(aesConf.first.algo.to_sym == :aes).to be true
      puts "Found #{c.native_config[:algo_str]}"
    end
  end

  it 'encrypt and decrypt using user input' do
   
    require 'ccrypto/ruby'

    ccc = Ccrypto::AlgoFactory.engine(Ccrypto::CipherConfig)
    testkey = ccc.supported_ciphers
    expect(testkey.length > 0).to be true

    testkey.each do |hc|
     
      enc = []
      spec = hc.clone
      spec.cipherOps = :encrypt

      if spec.has_min_input_length? #not_empty?(spec.min_input_length) and spec.min_input_length > 0
        # divide by 2 because  of hex character : 1 byte = 2 hex
        data = SecureRandom.hex(spec.min_input_length/2)
      else
        #data = SecureRandom.hex(4)
        data = "Testing data here"
      end

      # special handling for GCM & CCM mode
      if spec.is_auth_mode_cipher?
        spec.auth_data = "testing"
        if spec.is_mode?(:ccm)
          spec.plaintext_length = data.length
        end
      end

      cc = Ccrypto::AlgoFactory.engine(spec)
      expect(cc).not_to be nil

      #enc = cc.final(data)
      enc << cc.update(data)
      enc << cc.final

      ### Encryption done!

      spec.cipherOps = :decrypt

      # special handling for GCM & CCM mode
      if spec.is_mode?(:ccm)
        #spec.ciphertext_length = enc.length
        spec.ciphertext_length = enc.join.length
      end

      ccd = Ccrypto::AlgoFactory.engine(spec)

      dec = []
      enc.each do |e|
        dec << ccd.update(e) 
      end
      dec << ccd.final
      #dec = ccd.final(enc)

      #expect(dec == data).to be true
      expect(dec.join == data).to be true
      
    end

  end

  it 'encrypt and decrypt with AES GCM auth data' do

    cc = Ccrypto::AlgoFactory.engine(Ccrypto::CipherConfig)
    co = cc.get_cipher(:aes, 256, :gcm)
    expect(co.nil?).to be false
    expect(co.count == 2).to be true
    co = co.first
    co.auth_data = "this is external auth data"
    co.encrypt_cipher_mode

    conv = Ccrypto::UtilFactory.instance(:converter)

    enc = []
    data = ["first par tof the data", " second part of the data is fun"]
    c = Ccrypto::AlgoFactory.engine(co)
    res = c.update(data[0])
    puts "input length : #{data[0].length} / output length : #{res.length}"
    enc << res
    res = c.final(data[1])
    puts "input length : #{data[1].length} / output length : #{res.length}"
    enc << res
    puts "total encrypted : #{enc.join.length}"

    #puts "Encryption done #{conv.to_hex(enc.join)}"

    plain = []
    co.decrypt_cipher_mode
    d = Ccrypto::AlgoFactory.engine(co)
    plain << d.update(enc.join)
    plain << d.final

    expect(plain.join == data.join).to be true

  end

  it 'finds respective cipher config from finder interface' do


    cc = Ccrypto::AlgoFactory.engine(Ccrypto::CipherConfig)
    p cc.supported_cipher_list.algos

    [
      [:aes],
      [:aes, 256],
      [:aes, 256, :gcm],
      [:chacha20],
      [:chacha20, nil, :poly1305],
      [:camellia],
      [:camellia,256],
      [:camellia,256,:ctr],
      [:aria],
      [:aria,256],
      [:aria,256,:gcm],
      [:sm4],
      [:sm4,128],
      [:sm4,128,:ctr]
    ].each do |conf|

      puts "testing config #{conf}"
      co = cc.get_cipher(*conf)
      expect(co.nil?).to be false
      expect(co.empty?).to be false
      co.each do |cco|
        puts "conf : #{conf} / cco : #{cco}"
        expect(cco.algo.to_sym == conf[0]).to be true
        if conf.length > 1
          expect(cco.keysize == conf[1]).to be true if conf.length > 0 and not conf[1].nil?
        end

        if conf.length > 2
          puts "cco mode #{cco.mode} / #{conf[2]}"
          expect(cco.mode.to_sym == conf[2]).to be true if conf.length > 1
        end
      end

      #if (conf[0] == :chacha20 or conf[0] == :camellia or conf[0] == :aria or conf[0] == :sm4) and conf.length == 1
      #  puts co
      #end

    end
  end


end
