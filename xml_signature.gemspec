# encoding: utf-8
$:.push File.expand_path("../lib", __FILE__)
require "xml_signature/version"

Gem::Specification.new do |s|
  s.name        = "xml_signature"
  s.version     = XMLSignature::VERSION
  s.author      = "Kjell-Magne Øierud"
  s.email       = ["kjellm@oierud.net"]
  s.homepage    = "https://github.com/kjellm/xml_signature"
  s.license     = "MIT"
  s.summary     = %q{A (partial) implementation of the XML Signature standard}
  s.description = %q{A (partial) implementation of the XML Signature standard}
  
  s.files         = `git ls-files`.split("\n")
  #s.test_files    = `git ls-files -- spec/*`.split("\n")
  #s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.required_ruby_version = '>= 1.8.7'

  s.add_runtime_dependency 'xmlcanonicalizer'
end
