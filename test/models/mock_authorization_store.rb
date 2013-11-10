class MockAuthorizationStore
  
  def self.authorization(consumer_key, token)
    MockAuthorization.new if 'ck' == consumer_key && 'at' == token
  end  
  
end