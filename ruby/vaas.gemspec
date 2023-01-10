lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'vaas/version'
Gem::Specification.new do |s|
  s.name        = "vaas"
  s.version     = VaasMain::VERSION
  s.summary     = "Verdict as a Service by G Data"
  s.description = "Simple gem to get the verdict of files from G Data"
  s.authors     = ["Allie Weitenkamp"]
  s.email       = "allie.weitenkamp@gdata.de"
  s.files       = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  s.homepage    = "https://rubygems.org/gems/vaas"
  s.license     = "MIT"
  s.require_paths = ["lib"]
  s.bindir        = "exe"
  s.executables   = s.files.grep(%r{^exe/}) { |f| File.basename(f) }
end
