class MockAuthorization
    
  def credentials
    OoAuth::Credentials.new('ck', 'cs', 'at', 'as')
  end
  
end