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
  s.required_ruby_version = '>= 3.1.1'
  s.metadata = { "documentation_uri" => "https://github.com/GDATASoftwareAG/vaas/blob/main/ruby/README.md" }

  s.add_dependency 'async-http', '~> 0.59.4'
  s.add_dependency 'async-websocket', '~> 0.22.1'

  s.add_development_dependency "minitest", '~> 5.17.0'
end
