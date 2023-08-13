Pod::Spec.new do |s|
  s.name                        = "VirgilCryptoFoundation"
  s.version                     = "0.17.1-dev.2"
  s.swift_version               = "5.0"
  s.license                     = { :type => "BSD", :file => "LICENSE" }
  s.summary                     = "Contains basic swift classes for creating key pairs, encrypting/decrypting data, signing data and verifying signatures."
  s.homepage                    = "https://github.com/VirgilSecurity/virgil-crypto-c"
  s.authors                     = { "Virgil Security" => "https://virgilsecurity.com/" }
  s.source                      = { :git => "https://github.com/VirgilSecurity/virgil-crypto-c.git", :tag => "v" + s.version.to_s }
  s.ios.deployment_target       = "11.0"
  s.osx.deployment_target       = "10.13"
  s.tvos.deployment_target      = "11.0"
  s.watchos.deployment_target   = "4.0"
  s.public_header_files         = "wrappers/swift/VirgilCrypto/VirgilCryptoFoundation/VirgilCryptoFoundation.h"
  s.source_files                = "wrappers/swift/VirgilCrypto/VirgilCryptoFoundation/**/*.{h,mm,swift}"
  s.dependency "VSCCrypto/Common", "= 0.17.1-dev.2"
  s.dependency "VSCCrypto/Foundation", "= 0.17.1-dev.2"
end
