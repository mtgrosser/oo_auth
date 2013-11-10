class MockAuthorizationStore
  
  def self.authorization(consumer_key, token)
    MockAuthorization.new
  end  
  
end