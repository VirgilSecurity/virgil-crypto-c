Pod::Spec.new do |s|
  s.name                        = "VSCCrypto"
  s.version                     = "0.17.0"
  s.license                     = { :type => "BSD", :file => "VSCCrypto-XCFrameworks/LICENSE" }
  s.summary                     = "Contains basic c functions classes for creating key pairs, encrypting/decrypting data, signing data and verifying signatures."
  s.homepage                    = "https://github.com/VirgilSecurity/virgil-crypto-c"
  s.authors                     = { "Virgil Security" => "https://virgilsecurity.com/" }
  s.source                      = { :http => "https://github.com/VirgilSecurity/virgil-crypto-c/releases/download/v" + s.version.to_s + "/VSCCrypto.xcframework.zip" }
  s.ios.deployment_target       = "11.0"
  s.osx.deployment_target       = "10.13"
  s.tvos.deployment_target      = "11.0"
  s.watchos.deployment_target   = "4.0"

  s.subspec 'Common' do |sp|
    sp.vendored_frameworks     = "VSCCrypto-XCFrameworks/VSCCommon.xcframework"
  end

  s.subspec 'Foundation' do |sp|
    sp.vendored_frameworks     = "VSCCrypto-XCFrameworks/VSCFoundation.xcframework"
  end

  s.subspec 'Pythia' do |sp|
    sp.vendored_frameworks     = "VSCCrypto-XCFrameworks/VSCPythia.xcframework"
  end

  s.subspec 'Ratchet' do |sp|
    sp.vendored_frameworks     = "VSCCrypto-XCFrameworks/VSCRatchet.xcframework"
  end
end
