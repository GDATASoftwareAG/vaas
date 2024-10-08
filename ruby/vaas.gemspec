lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'vaas/version'
Gem::Specification.new do |s|
  s.name        = "vaas"
  s.version     = VAAS::VERSION
  s.summary     = "Verdict as a Service by G Data"
  s.description = "Simple gem to get the verdict of files from G Data"
  s.authors     = ["Allie Weitenkamp"]
  s.email       = "opensource@gdata.de"
  s.files       = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  s.homepage    = "https://github.com/GDATASoftwareAG/vaas"
  s.license     = "MIT"
  s.require_paths = ["lib"]
  s.metadata = { "documentation_uri" => "https://github.com/GDATASoftwareAG/vaas/blob/main/ruby/README.md" }
  s.required_ruby_version = '>= 3.1.1'

  s.add_dependency 'async', '~> 2.15.3'
  s.add_dependency 'async-http', '~> 0.70.0'
  s.add_dependency 'async-websocket', '~> 0.28.0'

  s.add_development_dependency "minitest", '~> 5.17.0'
  s.add_development_dependency 'dotenv', '~> 2.8.1'
end
