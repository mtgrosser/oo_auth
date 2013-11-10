require_relative '../test_helper'

class OoAuthTest < MiniTest::Unit::TestCase
  def setup
  
  end

  def test_hmac_sha_1
    assert_equal 'egQqG5AJep5sJ7anhXju1unge2I=', OoAuth::Signature.hmac_sha1_signature('bs', 'cs', nil)
    assert_equal 'VZVjXceV7JgPq/dOTnNmEfO0Fv8=', OoAuth::Signature.hmac_sha1_signature('bs', 'cs', 'ts')
    base_string = 'GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal'
    assert_equal 'tR3+Ty81lMeYAr/Fid0kMTYa/WM=', OoAuth::Signature.hmac_sha1_signature(base_string, 'kd94hf93k423kf44', 'pfkkdhi9sl3r4s00')
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
    http = Net::HTTP.new('photos.example.net', Net::HTTP.http_default_port)
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
  
  def test_normalized_request_uri_includes_nondefault_port_for_net_http_request
    http = Net::HTTP.new('www.example.net', 8080)
    http.use_ssl = true
    request = Net::HTTP::Get.new('/?q=1')
    assert_equal 'https://www.example.net:8080/', OoAuth::RequestProxy.new(http, request).normalized_request_uri
  end
  
  def test_normalized_request_uri_includes_nondefault_port_for_action_dispatch_request
    request = ActionDispatchMockRequest.new('GET', 'www.example.net', 8080, '/?q=1', true)
    assert_equal 'https://www.example.net:8080/', OoAuth::RequestProxy.new(request).normalized_request_uri
  end
  
  def test_signing_net_http_request
    http = Net::HTTP.new('example.com', 80)
    request = Net::HTTP::Get.new('/?n=v')
    proxy = OoAuth::RequestProxy.new(http, request)
    
    OoAuth::Signature.sign! proxy, MockAuthorization.new.credentials

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
  
  def test_signing_action_dispatch_request
    request = ActionDispatchMockRequest.new('GET', 'example.com', 80, '/?n=v', false)
    proxy = OoAuth::RequestProxy.new(request)
    
    OoAuth::Signature.sign! proxy, MockAuthorization.new.credentials

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
end