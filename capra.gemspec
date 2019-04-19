
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "capra/version"

Gem::Specification.new do |spec|
  spec.name          = "capra"
  spec.version       = Capra::VERSION
  spec.authors       = ["Kent 'picat' Gruber"]
  spec.email         = ["kgruber1@emich.edu"]

  spec.summary       = %q{Intrusion detection system.}
  # spec.description   = %q{TODO: Write a longer description or delete this line.}
  spec.homepage      = "https://github.com/picatz/capra"
  spec.license       = "MIT"

  spec.files         = Dir['lib/**/*.rb']
  spec.bindir        = 'bin'
  spec.executable    = 'capra'
  spec.require_paths = ['lib']

  spec.post_install_message = "Thank you for installing Capra!\nMake sure to install `libpcap-dev` if you haven't already!"

  spec.requirements << 'libpcap-dev'

  spec.add_dependency "packetgen", "~> 3.1.2"
  spec.add_dependency "oj", "~> 3.7.11"
  spec.add_dependency "command_lion", "~> 2.0.1"
  spec.add_dependency "ipaddr", "~> 1.2.2"

  spec.add_development_dependency "bundler", "~> 1.17"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.8.0"
  spec.add_development_dependency "pry", "~> 0.12.2"
  spec.add_development_dependency "pry-coolline", "~> 0.2.5"
end
