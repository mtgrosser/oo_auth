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

In your Rails API controller:

```ruby
class ApiController < ApplicationController

  before_action :oauth_required

  private
  
  def oauth_required
    if authorization = OoAuth.authorize!(request)
      self.current_user = authorization.user
    else
      render nothing: true, status: 401
      false
    end
  end
end
```

## Prerequisites for OAuth providers

OoAuth requires your provider application to provide stores for authorization tokens 
and OAuth nonces. (You won't need these stores if you're only using OoAuth's client
functionality.)

OoAuth stores can be simple lambdas or regular ruby objects.

### Authorization store

The authorization store is used for looking up OAuth credentials. It could for example
be an API account or user model. OoAuth will query the authorization store by calling
its method `authorization(consumer_key, token)` if it is a regular object, or just
call it with the same arguments if it is a lambda.

When the consumer key and token combination actually exists, the call should return
an object representing the API account (e.g. user instance, API account instance).

This instance again must implement the method `:credentials`, and return an instance
of `OoAuth::Credentials` initialized with the account's full credential set.

```ruby

# app/models/api_account.rb
class ApiAccount < ActiveRecord::Base

  def self.authorization(consumer_key, token)
    where(consumer_key: consumer_key, token: token).first
  end
  
  def credentials
    OoAuth::Credentials.new(consumer_key, consumer_secret, token, token_secret)
  end
end

# config/initializers/oo_auth.rb
OoAuth.authorization_store =  ApiAccount
```

### Nonce store

The nonce store is needed by provider applications to temporarily store OAuth nonces.
It must provide a `remember(nonce)` method or be a callable proc, where `nonce` is an
instance of `OoAuth::Nonce`. 

The store must ensure that each tuple `(timestamp, nonce value)` is only created once.
This is required by the OAuth spec in order to prevent replay attacks.

```ruby
# app/models/nonce.rb
class Nonce < ActiveRecord::Base
  validates_presence_of :value, :timestamp
  validates_uniqueness_of :value, scope: :timestamp
  
  def self.remember(ooauth_nonce)
    new(value: ooauth_nonce.value, ooauth_nonce.timestamp).save
  end
end

# config/initializers/oo_auth.rb
OoAuth.nonce_store = Nonce
```

OoAuth comes with a pre-defined Redis nonce store, which can be enabled as following:
```ruby
# Gemfile
gem 'redis'

# config/initializers/oo_auth.rb
require 'oo_auth/nonce/redis_store'

OoAuth.nonce_store = OoAuth::Nonce::RedisStore.new(namespace: 'foobar')
```

## Configuring signature methods

The available signature methods can be configured using a setter which accepts
signature method names as strings or symbols:

```ruby
# config/initializers/oo_auth.rb
OoAuth.signature_methods = [:hmac_sha1, 'HMAC-SHA256', :hmac_sha512]
```

The default signature method OoAuth will use to sign requests is `HMAC-SHA1`.
It can be set to any of the supported methods using

```ruby
OoAuth.signature_method = :hmac_sha256
```

As using `HMAC-SHA1` is no longer recommended, you can disable it altogether:

```ruby
# disable HMAC-SHA1 completely
OoAuth.signature_methods = [:hmac_sha256]
```

A provider configured this way will only accept `HMAC-SHA256` signatures.

## TODO

* Support POST body signing for non-formencoded data
  http://oauth.googlecode.com/svn/spec/ext/body_hash/1.0/oauth-bodyhash.html
