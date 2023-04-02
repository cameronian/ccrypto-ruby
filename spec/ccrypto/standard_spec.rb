
require 'openssl'

RSpec.describe "Create standard sample code for algos as it might changed between versions" do

  context "Only for OpenSSL v3 and above", if: OpenSSL::VERSION >= "3.0.0" do

    it 'creates cipher for GCM mode' do

      c = OpenSSL::Cipher.new("aes-256-gcm")
      c.encrypt
      key = c.random_key
      iv = c.random_iv
      c.auth_data = "my login"

      data = "confidential data here"

      res = c.update(data) + c.final
      atag = c.auth_tag

      d = OpenSSL::Cipher.new("aes-256-gcm")
      d.decrypt
      d.key = key
      d.iv = iv
      d.auth_data = "my login"
      d.auth_tag = atag

      plain = d.update(res) + d.final
      expect(plain == data).to be true

      # test without passing the auth_tag
      d = OpenSSL::Cipher.new("aes-256-gcm")
      d.decrypt
      d.key = key
      d.iv = iv
      d.auth_data = "my login"

      expect {
        d.update(res) + d.final
      }.to raise_exception(OpenSSL::Cipher::CipherError)

    end

    it 'create cipher for aes-128-ocb ' do

      adata = "login"

      c = OpenSSL::Cipher.new("aes-128-ocb")
      c.encrypt
      iv = c.random_iv
      key = c.random_key

      c.auth_data = adata

      data = SecureRandom.hex(20)
      res = c.update(data) + c.final
      atag = c.auth_tag

      d = OpenSSL::Cipher.new("aes-128-ocb")
      d.decrypt
      d.key = key
      d.iv = iv

      d.auth_data = adata
      d.auth_tag = atag

      dres = d.update(res) + d.final

      expect(dres == data).to be true

    end

    it 'create cipher for aes-128-xts ' do

      adata = "login"

      algo = "aes-128-xts"
      c = OpenSSL::Cipher.new(algo)
      puts "authenticated? : #{c.authenticated?}"
      c.encrypt
      iv = c.random_iv
      puts "iv length : #{c.iv_len}"
      key = c.random_key

      max = 64
      cnt = 0
      loop do
        begin

          data = SecureRandom.hex(cnt)
          res = c.update(data) + c.final

          d = OpenSSL::Cipher.new(algo)
          d.decrypt
          d.key = key
          d.iv = iv

          dres = d.update(res) + d.final

          expect(dres == data).to be true

          STDOUT.puts "Success on data length #{data.length} / #{data}"

          break if cnt >= max

        rescue OpenSSL::Cipher::CipherError => ex
          STDERR.puts "Error on data length #{cnt} : #{ex.message}"
        ensure
          cnt += 1
        end
      end
    end

    it 'create cipher for aes128-wrap ' do

      adata = "login"

      algo = "aes128-wrap"
      c = OpenSSL::Cipher.new(algo)
      puts "authenticated? : #{c.authenticated?}"
      c.encrypt
      iv = c.random_iv
      puts "iv length : #{c.iv_len}"
      key = c.random_key

      max = 64
      cnt = 0
      loop do
        begin

          data = SecureRandom.hex(cnt)
          res = c.update(data) + c.final

          d = OpenSSL::Cipher.new(algo)
          d.decrypt
          d.key = key
          d.iv = iv

          dres = d.update(res) + d.final

          expect(dres == data).to be true

          STDOUT.puts "aes128-wrap Success on data length #{data.length} / #{data}"

          break if cnt >= max

        rescue OpenSSL::Cipher::CipherError => ex
          STDERR.puts "aes128-wrap Error on data length #{cnt} : #{ex.message}"
        ensure
          cnt += 1
        end
      end
    end

    it 'create cipher for des3-wrap ' do

      adata = "login"

      algo = "des3-wrap"
      c = OpenSSL::Cipher.new(algo)
      puts "authenticated? : #{c.authenticated?}"
      c.encrypt
      iv = c.random_iv
      puts "iv length : #{c.iv_len}"
      key = c.random_key

      data = SecureRandom.hex(4)
      res = c.update(data) + c.final

      d = OpenSSL::Cipher.new(algo)
      d.decrypt
      d.key = key
      d.iv = iv

      dres = d.update(res) + d.final

      expect(dres == data).to be true

    end


    it 'creates cipher for CCM mode' do

      adata = "my login"
      data = "super secret for testing"
      puts "data length : #{data.length}"


      [7,8,9,10,11,12,13].each do |atl|

        begin
          c = OpenSSL::Cipher.new("aes-256-ccm")
          c.encrypt
          key = c.random_key
          iv = c.random_iv
          expect(iv.length > 0).to be true
          puts "Iv length : #{iv.length}"

          c.ccm_data_len = data.length
          c.auth_data = adata
          # must set this to 12
          c.auth_tag_len = atl

          res = c.update(data)
          res += c.final
          tag = c.auth_tag
          STDOUT.puts "Tag length : #{atl} works!"
        rescue OpenSSL::Cipher::CipherError => ex
          STDERR.puts "Error on tag length '#{atl}' : #{ex.message}"
        end

      end

      c = OpenSSL::Cipher.new("aes-256-ccm")
      c.encrypt
      key = c.random_key
      iv = c.random_iv
      expect(iv.length > 0).to be true

      c.ccm_data_len = data.length
      c.auth_data = adata
      # must set this to 12
      c.auth_tag_len = 12

      res = c.update(data)
      res += c.final
      tag = c.auth_tag


      d = OpenSSL::Cipher.new("aes-256-ccm")
      d.decrypt
      d.key = key
      d.iv = iv

      d.ccm_data_len = res.length
      d.auth_data = adata
      d.auth_tag = tag

      dres = d.update(res) + d.final
      expect(dres == data).to be true

    end

    it 'creates cipher for cbc-hmac-sha1' do

      algo = "aes-128-cbc-hmac-sha1"

      # crash Ruby!
      #cnt1 = 0
      #cnt2 = 0
      #loop do

      #  begin

      #    data = SecureRandom.hex(cnt1)
      #    adata = SecureRandom.hex(cnt2)
      #    puts "data length : #{data.length}"

      #    c = OpenSSL::Cipher.new(algo)
      #    c.encrypt
      #    key = c.random_key
      #    iv = c.random_iv
      #    expect(iv.length > 0).to be true

      #    # must set this to 12
      #    c.auth_tag_len = 12
      #    c.auth_data = adata

      #    res = c.update(data)
      #    res += c.final
      #    tag = c.auth_tag

      #    puts "Length #{cnt1} / #{cnt2} is good"

      #  rescue OpenSSL::Cipher::CipherError => ex
      #    STDERR.puts "Data size #{cnt1} / #{cnt2} failed : #{ex.message}"
      #  ensure 
      #    cnt1 += 1
      #    if cnt1 >= 64
      #      cnt2 += 1
      #    end

      #    if cnt2 >= 64
      #      break
      #    end
      #  end
      #end

      data = SecureRandom.hex(16)
      #adata = SecureRandom.hex(11)
      adata = ""
      puts "data length : #{data.length}"

      c = OpenSSL::Cipher.new(algo)
      c.encrypt
      key = c.random_key
      iv = c.random_iv
      expect(iv.length > 0).to be true

      c.auth_data = adata

      res = c.update(data)
      res += c.final
      tag = c.auth_tag

      d = OpenSSL::Cipher.new(algo)
      d.decrypt
      d.key = key
      d.iv = iv

      d.auth_data = adata
      d.auth_tag = tag

      dres = d.update(res) + d.final
      expect(dres == data).to be true

    end

    it 'creates cipher for cbc-hmac-sha256' do

      algo = "aes-128-cbc-hmac-sha256"

      data = SecureRandom.hex(32)
      #adata = SecureRandom.hex(11)
      adata = ""
      puts "data length : #{data.length}"

      c = OpenSSL::Cipher.new(algo)
      c.encrypt
      key = c.random_key
      iv = c.random_iv
      expect(iv.length > 0).to be true

      c.auth_data = adata

      res = c.update(data)
      res += c.final
      tag = c.auth_tag

      d = OpenSSL::Cipher.new(algo)
      d.decrypt
      d.key = key
      d.iv = iv

      d.auth_data = adata
      d.auth_tag = tag

      dres = d.update(res) + d.final
      expect(dres == data).to be true

    end


  end # if OpenSSL v3

end
