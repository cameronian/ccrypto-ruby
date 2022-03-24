

module Ccrypto
  module Ruby
    class ComparatorUtil
      include DataConversion

      def self.is_equal?(val1, val2)
        val1 == val2
      end
      self.singleton_class.alias_method :is_equals?, :is_equal?

    end
  end
end
