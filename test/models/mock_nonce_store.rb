class MockNonceStore < OoAuth::Nonce::AbstractStore
  
  def nonces
    @nonces ||= {}
  end
  
  def remember(nonce)
    return false if nonces.has_key?(key(nonce))
    nonces[key(nonce)] = nonce
  end
  
  private
  
  def key(nonce)
    "#{nonce.timestamp}:#{nonce.value}"
  end
end
