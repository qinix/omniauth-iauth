# -*- encoding: utf-8 -*-
require File.expand_path('../lib/omniauth-iauth/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ["Eric Zhang"]
  gem.email         = ["i@qinix.com"]
  gem.description   = %q{A generic IAuth (1.0/1.0a) strategy for OmniAuth.}
  gem.summary       = %q{A generic IAuth (1.0/1.0a) strategy for OmniAuth.}
  gem.homepage      = "https://github.com/qinix/omniauth-iauth"

  gem.add_runtime_dependency 'omniauth'
  gem.add_runtime_dependency 'iauth'
  gem.add_development_dependency 'rake'
  gem.add_development_dependency 'pry'

  gem.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  gem.files         = `git ls-files`.split("\n")
  gem.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  gem.name          = "omniauth-iauth"
  gem.require_paths = ["lib"]
  gem.version       = OmniAuth::IAuth::VERSION
end
