[![Gem Version](https://badge.fury.io/rb/oo_auth.png)](http://badge.fury.io/rb/oo_auth) [![Code Climate](https://codeclimate.com/github/mtgrosser/oo_auth.png)](https://codeclimate.com/github/mtgrosser/oo_auth)

# oo_auth

OAuth Out Of Band - Sign, verify and authorize OAuth requests

OoAuth is a stripped-down implementation of the OAuth 1.0a protocol.

It only cares for signing and verifying OAuth requests, supporting both
```Net::HTTP``` and  ```ActionDispatch::Request```.

OoAuth does not include any models or controllers dealing with token and
secret exchange, storage or lookup. Instead, it offers a simplistic API
where you can hook your own implementations as desired.

OoAuth comes with optional Redis support for short-time high performance storage
of OAuth nonces.

It can be used for implementing OAuth consumers as well as providers.

## Install

In your Gemfile:

```ruby
gem 'oo_auth'
```

## Prerequisites

OoAuth requires your application to provide stores for authorization tokens 
and OAuth nonces.

OoAuth stores can be simple lambdas or regular ruby objects.

### Authorization store

The authorization store should return an instance of ```OoAuth::Credentials```.
It can either be a lambda or an object implementing the `authorization` method.

```ruby
# your own implementation in SomeClass model
OoAuth.authorization_store = lambda { |consumer_key, token| SomeClass.find_by_tokens(consumer_key, token) }
```
```ruby
# direct lookup
OoAuth.authorization_store = User
```
### Nonce store
```ruby
require 'oo_auth/nonce/redis_store'

OoAuth.nonce_store = OoAuth::Nonce::RedisStore.new(namespace: 'foobar')
```
## Use

### OAuth consumer

```ruby
http = Net::HTTP.new('photos.example.net', Net::HTTP.http_default_port)
request = Net::HTTP::Get.new('/photos?file=vacation.jpg&size=original')

credentials = OoAuth::Credentials.new('consumer_key',
                                      'consumer_secret',
                                      'access_token',
                                      'access_token_secret')

OoAuth.sign!(http, request, credentials)

request['Authorization']
=> "OAuth oauth_version=\"1.0\", oauth_nonce=\"ly9V24IvFMhEGSlGW1tPniUVnVzQkWvn4W6Bwtmc4\", oauth_timestamp=\"1384116351\", oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"consumer_key\", oauth_token=\"access_token\", oauth_signature=\"5G1ktyWhicZGnSu2AKkjok9%2BMPo%3D\""
```

### OAuth provider

```ruby
class FoobarController < ApplicationController

  before_filter :oauth_required

  private
  
  def oauth_required
    if authorization = OoAuth.authorize!(request)
      self.current_user = authorization.user
    else
      render nothing: true, status: 401
    end
  end
```


## TODO

* Support POST body signing
