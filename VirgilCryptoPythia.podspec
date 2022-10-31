Pod::Spec.new do |s|
  s.name                        = "VirgilCryptoPythia"
  s.version                     = "0.16.4-dev3"
  s.swift_version               = "5.0"
  s.license                     = { :type => "BSD", :file => "LICENSE" }
  s.summary                     = "Contains swift classes working with Pythia crypto."
  s.homepage                    = "https://github.com/VirgilSecurity/virgil-crypto-c"
  s.authors                     = { "Virgil Security" => "https://virgilsecurity.com/" }
  s.source                      = { :git => "https://github.com/VirgilSecurity/virgil-crypto-c.git", :tag => "v" + s.version.to_s }
  s.ios.deployment_target       = "11.0"
  s.osx.deployment_target       = "10.9"
  s.tvos.deployment_target      = "11.0"
  s.watchos.deployment_target   = "4.0"
  s.public_header_files         = "wrappers/swift/VirgilCrypto/VirgilCryptoPythia/VirgilCryptoPythia.h"
  s.source_files                = "wrappers/swift/VirgilCrypto/VirgilCryptoPythia/**/*.{h,mm,swift}"
  s.dependency "VirgilCryptoFoundation", "= 0.16.4-dev3"
  s.dependency "VSCCrypto/Common", "= 0.16.4-dev3"
  s.dependency "VSCCrypto/Foundation", "= 0.16.4-dev3"
  s.dependency "VSCCrypto/Pythia", "= 0.16.4-dev3"
end
