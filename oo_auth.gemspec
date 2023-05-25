$:.push File.expand_path("../lib", __FILE__)

require "oo_auth/version"

Gem::Specification.new do |s|
  s.name = "oo_auth"
  s.version = OoAuth::VERSION

  s.authors = ["Matthias Grosser"]
  s.date = "2023-05-25"
  s.description = "Out Of Band OAuth"
  s.email = "mtgrosser@gmx.net"
  s.homepage = "http://github.com/mtgrosser/oo_auth"
  s.files = Dir['{lib}/**/*.rb', 'LICENSE', 'README.md', 'CHANGELOG']
  s.require_paths = ["lib"]
  s.summary = "OAuth without the callbacks"
  s.license = 'MIT'
  
  s.required_ruby_version  = '>= 3.0'
end
