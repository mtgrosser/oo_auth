require_relative '../test_helper'

class OoAuthTest < MiniTest::Unit::TestCase
  def setup
    OoAuth.nonce_store = MockNonceStore.new
    OoAuth.authorization_store = MockAuthorizationStore
    
    @twitter_credentials = 
      OoAuth::Credentials.new('xvz1evFS4wEEPTGEFPHBog',
                              'kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw',
                              '370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb',
                              'LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE')
    @twitter_nonce = 'kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg'
    @twitter_timestamp = 1318622958
    request = ActionDispatchMockRequest.new('POST', 'api.twitter.com', 443,
                                            '/1/statuses/update.json?include_entities=true',
                                            true,
                                            body: 'status=Hello%20Ladies%20%2b%20Gentlemen%2c%20a%20signed%20OAuth%20request%21',
                                            headers: { 'Content-Type' => 'application/x-www-form-urlencoded',
                                                       'Authorization' => 'OAuth oauth_consumer_key="xvz1evFS4wEEPTGEFPHBog", oauth_version="1.0", oauth_nonce="kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg", oauth_timestamp="1318622958", oauth_signature_method="HMAC-SHA1", oauth_signature="tnnArxj06cWHq44gCs1OSKk%2FjLY%3D", oauth_token="370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"' })
    @twitter_proxy = OoAuth::RequestProxy.new(request)
    @twitter_mock_key = "#{@twitter_timestamp}:#{@twitter_nonce}"
  end

  def test_hmac_sha_1
    assert_equal 'egQqG5AJep5sJ7anhXju1unge2I=', OoAuth::Signature.send(:hmac_signature, 'HMAC-SHA1', 'bs', 'cs', nil)
    assert_equal 'VZVjXceV7JgPq/dOTnNmEfO0Fv8=', OoAuth::Signature.send(:hmac_signature, 'HMAC-SHA1', 'bs', 'cs', 'ts')
    base_string = 'GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal'
    assert_equal 'tR3+Ty81lMeYAr/Fid0kMTYa/WM=', OoAuth::Signature.send(:hmac_signature, 'HMAC-SHA1', base_string, 'kd94hf93k423kf44', 'pfkkdhi9sl3r4s00')
  end
  
  def test_signature_base_string_from_net_http_request
    http = Net::HTTP.new('example.com', Net::HTTP.http_default_port)
    request = Net::HTTP::Get.new('/?n=v')
    proxy = OoAuth::RequestProxy.new(http, request)
    assert_equal 'GET&http%3A%2F%2Fexample.com%2F&n%3Dv', proxy.signature_base_string
  end
  
  def test_signature_base_string_from_action_dispatch_request
    request = ActionDispatchMockRequest.new('GET', 'example.com', 80, '/?n=v', false)
    proxy = OoAuth::RequestProxy.new(request)
    assert_equal 'GET&http%3A%2F%2Fexample.com%2F&n%3Dv', proxy.signature_base_string
  end
  
  def test_signature_base_string_with_params_from_net_http_request
    http = Net::HTTP.new('photos.example.net', Net::HTTP.http_default_port)
    request = Net::HTTP::Get.new('/photos?file=vacation.jpg&size=original')
    params = {
      'oauth_version' => '1.0',
      'oauth_consumer_key' => 'dpf43f3p2l4k3l03',
      'oauth_token' => 'nnch734d00sl2jdk',
      'oauth_timestamp' => '1191242096',
      'oauth_nonce' => 'kllo9940pd9333jh',
      'oauth_signature_method' => 'HMAC-SHA1'
    }

    base_string = 'GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal'
    assert_equal base_string, OoAuth::RequestProxy.new(http, request).signature_base_string(params)
  end
  
  def test_signature_base_string_with_params_from_action_dispatch_request
    request = ActionDispatchMockRequest.new('GET', 'photos.example.net', 80, '/photos?file=vacation.jpg&size=original', false)
    params = {
      'oauth_version' => '1.0',
      'oauth_consumer_key' => 'dpf43f3p2l4k3l03',
      'oauth_token' => 'nnch734d00sl2jdk',
      'oauth_timestamp' => '1191242096',
      'oauth_nonce' => 'kllo9940pd9333jh',
      'oauth_signature_method' => 'HMAC-SHA1'
    }

    base_string = 'GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal'
    assert_equal base_string, OoAuth::RequestProxy.new(request).signature_base_string(params)
  end
  
  def test_normalized_request_uri_excludes_default_port_for_net_http_request
    http = Net::HTTP.new('EXAMPLE.COM', Net::HTTP.http_default_port)
    request = Net::HTTP::Get.new('/r%20v/X?id=123')
    assert_equal 'http://example.com/r%20v/X', OoAuth::RequestProxy.new(http, request).normalized_request_uri
  end
  
  def test_normalized_request_uri_excludes_default_port_for_action_dispatch_request
    request = ActionDispatchMockRequest.new('GET', 'EXAMPLE.COM', 80, '/r%20v/X?id=123', false)
    assert_equal 'http://example.com/r%20v/X', OoAuth::RequestProxy.new(request).normalized_request_uri
  end
  
  def test_normalized_request_uri_includes_nondefault_port_for_net_http_ssl_request
    http = Net::HTTP.new('www.example.net', 8080)
    http.use_ssl = true
    request = Net::HTTP::Get.new('/?q=1')
    assert_equal 'https://www.example.net:8080/', OoAuth::RequestProxy.new(http, request).normalized_request_uri
  end

  def test_normalized_request_uri_includes_nondefault_port_for_net_http_request
    http = Net::HTTP.new('www.example.net', 8080)
    http.use_ssl = false
    request = Net::HTTP::Get.new('/?q=1')
    assert_equal 'http://www.example.net:8080/', OoAuth::RequestProxy.new(http, request).normalized_request_uri
  end
  
  def test_normalized_request_uri_includes_nondefault_port_for_action_dispatch_request
    request = ActionDispatchMockRequest.new('GET', 'www.example.net', 8080, '/?q=1', true)
    assert_equal 'https://www.example.net:8080/', OoAuth::RequestProxy.new(request).normalized_request_uri
  end
  
  def test_signing_net_http_get_request
    http = Net::HTTP.new('example.com', 80)
    request = Net::HTTP::Get.new('/?n=v')
    proxy = OoAuth::RequestProxy.new(http, request)
    
    OoAuth::Signature.sign! proxy, MockAuthorization.new.credentials, :hmac_sha1

    assert header = request['Authorization']
    assert_equal header, proxy.authorization
    
    assert_match /\AOAuth /, header
    assert_match /\boauth_version="1.0"/, header
    assert_match /\boauth_nonce="[^"]+"/, header
    assert_match /\boauth_timestamp="\d+"/, header
    assert_match /\boauth_signature_method="HMAC-SHA1"/, header
    assert_match /\boauth_consumer_key="ck"/, header
    assert_match /\boauth_signature="[^"]+"/, header
  end
  
  def test_signing_action_dispatch_get_request
    request = ActionDispatchMockRequest.new('GET', 'example.com', 80, '/?n=v', false)
    proxy = OoAuth::RequestProxy.new(request)
    
    OoAuth::Signature.sign! proxy, MockAuthorization.new.credentials, :hmac_sha1

    assert header = request.headers['Authorization']
    assert_equal header, proxy.authorization
    
    assert_match /\AOAuth /, header
    assert_match /\boauth_version="1.0"/, header
    assert_match /\boauth_nonce="[^"]+"/, header
    assert_match /\boauth_timestamp="\d+"/, header
    assert_match /\boauth_signature_method="HMAC-SHA1"/, header
    assert_match /\boauth_consumer_key="ck"/, header
    assert_match /\boauth_signature="[^"]+"/, header
  end
  
  def test_signing_net_http_post_request_with_urlencoded_body_using_hmac_sha1
    http = Net::HTTP.new('api.twitter.com', 443)
    http.use_ssl = true
    request = Net::HTTP::Post.new('/1/statuses/update.json?include_entities=true')
    request.body = 'status=Hello%20Ladies%20%2b%20Gentlemen%2c%20a%20signed%20OAuth%20request%21'
    request['Content-Type'] = 'application/x-www-form-urlencoded'
    proxy = OoAuth::RequestProxy.new(http, request)   
    oauth_params = { oauth_version: '1.0',
                     oauth_nonce: @twitter_nonce,
                     oauth_timestamp: @twitter_timestamp,
                     oauth_signature_method: 'HMAC-SHA1',
                     oauth_consumer_key: @twitter_credentials.consumer_key,
                     oauth_token: @twitter_credentials.token }
    
    signature = OoAuth::Signature.send(:calculate_signature, proxy, @twitter_credentials, oauth_params, 'HMAC-SHA1')
    
    assert_equal 'tnnArxj06cWHq44gCs1OSKk/jLY=', signature
  end
  
  def test_signing_net_http_post_request_with_urlencoded_body_using_hmac_sha256
    http = Net::HTTP.new('api.twitter.com', 443)
    http.use_ssl = true
    request = Net::HTTP::Post.new('/1/statuses/update.json?include_entities=true')
    request.body = 'status=Hello%20Ladies%20%2b%20Gentlemen%2c%20a%20signed%20OAuth%20request%21'
    request['Content-Type'] = 'application/x-www-form-urlencoded'
    proxy = OoAuth::RequestProxy.new(http, request)   
    oauth_params = { oauth_version: '1.0',
                     oauth_nonce: @twitter_nonce,
                     oauth_timestamp: @twitter_timestamp,
                     oauth_signature_method: 'HMAC-SHA256',
                     oauth_consumer_key: @twitter_credentials.consumer_key,
                     oauth_token: @twitter_credentials.token }
    
    signature = OoAuth::Signature.send(:calculate_signature, proxy, @twitter_credentials, oauth_params, 'HMAC-SHA256')
    
    assert_equal 'lrpvd+UOGVsQnRf5skaXYTNeIPFJ0C+qK3OGpK/XB9Q=', signature
  end
  
  def test_validating_action_dispatch_request
    Timecop.travel Time.at(@twitter_timestamp) do
      assert_equal true,  OoAuth::Signature.valid?(@twitter_proxy, @twitter_credentials)
      assert_equal false, OoAuth.nonce_store.nonces.include?(@twitter_mock_key)
    end
  end
  
  def test_validating_action_dispatch_request_respects_timestamp_deviation
    Timecop.travel Time.at(@twitter_timestamp + OoAuth::MAX_TIMESTAMP_DEVIATION + 3600) do
      assert_equal false,  OoAuth::Signature.valid?(@twitter_proxy, @twitter_credentials)
    end
  end
  
  def test_verifying_action_dispatch_request_remembers_nonce
    Timecop.travel Time.at(@twitter_timestamp) do
      assert_equal false, OoAuth.nonce_store.nonces.include?(@twitter_mock_key)
      assert_equal true,  OoAuth::Signature.verify!(@twitter_proxy, @twitter_credentials)
      assert_equal true,  OoAuth.nonce_store.nonces.include?(@twitter_mock_key)
      assert_equal false, OoAuth::Signature.verify!(@twitter_proxy, @twitter_credentials)
      assert_equal true,  OoAuth::Signature.valid?(@twitter_proxy, @twitter_credentials)
    end
  end
  
  def test_authorization
    request = ActionDispatchMockRequest.new('GET', 'photos.example.net', 80, '/photos?file=vacation.jpg&size=original', false)
    proxy = OoAuth::RequestProxy.new(request)
    credentials = MockAuthorization.new.credentials
    OoAuth::Signature.sign!(proxy, credentials)
    
    assert_equal 0, OoAuth.nonce_store.nonces.size
    assert authorization = OoAuth.authorize!(request)
    assert_equal 1, OoAuth.nonce_store.nonces.size
    assert_kind_of MockAuthorization, authorization
  end

  def test_authorization_failure
    request = ActionDispatchMockRequest.new('GET', 'photos.example.net', 80, '/photos?file=vacation.jpg&size=original', false)
    assert_nil OoAuth.authorize!(request)
  end
  
  def test_authorization_store_proc
    OoAuth.authorization_store = lambda { |consumer_key, token| MockAuthorization.new if 'ck' == consumer_key && 'at' == token }
    assert_nil OoAuth.authorization('ck', 'to')
    assert_kind_of MockAuthorization, OoAuth.authorization('ck', 'at')
  end
  
  def test_authorization_store_raises_configuration_error
    OoAuth.authorization_store = Object.new
    assert_raises OoAuth::ConfigurationError do
      OoAuth.authorization('ck', 'to')
    end
  end
  
  def test_nonce_store_proc
    store = MockNonceStore.new
    OoAuth.nonce_store = lambda { |nonce| store.remember(nonce) }
    assert OoAuth::Nonce.remember('foo', 123456)
    assert_equal false, OoAuth::Nonce.remember('foo', 123456)
  end
  
  def test_nocne_store_raises_configuration_error
    OoAuth.nonce_store = Object.new
    assert_raises OoAuth::ConfigurationError do
      OoAuth::Nonce.remember('bar', 123456)
    end
  end
  
  def test_credentials
    credentials = OoAuth::Credentials.generate
    assert_kind_of OoAuth::Credentials, credentials
    assert_equal [:consumer_key, :consumer_secret, :token, :token_secret], credentials.attributes.keys
    assert_equal true, credentials.attributes.values.all? { |value| value.size > 10 }
  end
  
  def test_generation_of_nonce_includes_timestamp
    nonce = OoAuth::Nonce.generate
    assert_kind_of OoAuth::Nonce, nonce
    assert nonce.timestamp >= Time.now.utc.to_i
    assert nonce.value.size > 5
  end
  
  def test_signing_net_http_request
    http = Net::HTTP.new('photos.example.net', Net::HTTP.http_default_port)
    request = Net::HTTP::Get.new('/photos?file=vacation.jpg&size=original')

    credentials = OoAuth::Credentials.new('consumer_key',
                                          'consumer_secret',
                                          'access_token',
                                          'access_token_secret')

    OoAuth.sign!(http, request, credentials)
    assert request['Authorization'].start_with?('OAuth ')
  end
  
  def test_setting_unsupported_signature_method_raises_error
    assert_raises OoAuth::UnsupportedSignatureMethod do
      OoAuth.signature_methods = [:hmac_sha1, :hmac_sha1024]
    end
  end
  
  def test_credentials_to_a
    credentials = OoAuth::Credentials.new('consumer_key',
                                          'consumer_secret',
                                          'access_token',
                                          'access_token_secret')
    assert_equal ['consumer_key', 'consumer_secret', 'access_token', 'access_token_secret'], credentials.to_a
  end
end
