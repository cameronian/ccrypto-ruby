# frozen_string_literal: true

require 'openssl'
require 'tlogger'
require 'toolrack'

require 'ccrypto'


require_relative "ruby/version"

require_relative 'provider'

require_relative 'ruby/ext/secret_key'
require_relative 'ruby/ext/x509_cert'

module Ccrypto
  module Ruby
    class Error < StandardError; end
    # Your code goes here...
  end
end

require 'ccrypto'
Ccrypto::Provider.instance.register(Ccrypto::Ruby::Provider)
