$:.push File.expand_path("../lib", __FILE__)

require "oo_auth/version"

Gem::Specification.new do |s|
  s.name = "oo_auth"
  s.version = OoAuth::VERSION

  s.authors = ["Matthias Grosser"]
  s.date = "2013-11-04"
  s.description = "Out Of Band OAuth"
  s.email = "mtgrosser@gmx.net"
  s.homepage = "http://github.com/mtgrosser/oo_auth"
  s.files = Dir['{lib}/**/*.rb', 'LICENSE', 'README.md', 'CHANGELOG']
  s.require_paths = ["lib"]
  s.rubygems_version = "2.0.3"
  s.summary = "OAuth without the callbacks"
  s.license = 'MIT'

  #s.add_dependency(%q<activesupport>, ["~> 3.2.13"])
  #s.add_dependency(%q<redis>, [">= 0"])

  s.add_development_dependency(%q<byebug>, [">= 0"])
  s.add_development_dependency(%q<simplecov>, [">= 0"])
  s.add_development_dependency(%q<rake>, [">= 0.8.7"])
  s.add_development_dependency(%q<minitest>, ["~> 4.7"])
end

