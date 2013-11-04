# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "oo_auth"
  s.version = "0.0.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Matthias Grosser"]
  s.date = "2013-11-04"
  s.description = "Out Of Band OAuth"
  s.email = "mtgrosser@gmx.net"
  s.homepage = "http://github.com/mtgrosser/oo_auth"
  s.require_paths = ["lib"]
  s.rubygems_version = "2.0.3"
  s.summary = "OAuth without the callbacks"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<activesupport>, ["~> 3.2.13"])
      s.add_development_dependency(%q<redis>, [">= 0"])
      s.add_development_dependency(%q<debugger>, [">= 0"])
      s.add_development_dependency(%q<simplecov>, [">= 0"])
      s.add_development_dependency(%q<rake>, [">= 0.8.7"])
    else
      s.add_dependency(%q<activesupport>, ["~> 3.2.13"])
      s.add_dependency(%q<redis>, [">= 0"])
      s.add_dependency(%q<debugger>, [">= 0"])
      s.add_dependency(%q<simplecov>, [">= 0"])
      s.add_dependency(%q<rake>, [">= 0.8.7"])
    end
  else
    s.add_dependency(%q<activesupport>, ["~> 3.2.13"])
    s.add_dependency(%q<redis>, [">= 0"])
    s.add_dependency(%q<debugger>, [">= 0"])
    s.add_dependency(%q<simplecov>, [">= 0"])
    s.add_dependency(%q<rake>, [">= 0.8.7"])
  end
end
