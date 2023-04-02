

require 'openssl'

res = {}
start = 0x0300
OpenSSL::PKey::EC.builtin_curves.sort.each do |c|
  next if c[0] =~ /^wap/
  res[c[0]] = ("0x%.4x" % start)
  start += 1
end

pp res
