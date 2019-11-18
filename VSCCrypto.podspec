Pod::Spec.new do |s|
  s.name                        = "VSCCrypto"
  s.version                     = "0.11.1"
  s.license                     = { :type => "BSD", :file => "Carthage/LICENSE" }
  s.summary                     = "Contains basic c functions classes for creating key pairs, encrypting/decrypting data, signing data and verifying signatures."
  s.homepage                    = "https://github.com/VirgilSecurity/virgil-crypto-c"
  s.authors                     = { "Virgil Security" => "https://virgilsecurity.com/" }
  s.source                      = { :http => "https://github.com/VirgilSecurity/virgil-crypto-c/releases/download/v0.11.1/VSCCrypto.framework.zip" }
  s.ios.deployment_target       = "9.0"
  s.osx.deployment_target       = "10.9"
  s.tvos.deployment_target      = "9.0"
  s.watchos.deployment_target   = "2.0"

  s.subspec 'Common' do |sp|
    sp.ios.vendored_frameworks     = "Carthage/iOS/VSCCommon.framework"
    sp.osx.vendored_frameworks     = "Carthage/macOS/VSCCommon.framework"
    sp.tvos.vendored_frameworks    = "Carthage/tvOS/VSCCommon.framework"
    sp.watchos.vendored_frameworks = "Carthage/watchOS/VSCCommon.framework"
  end

  s.subspec 'Foundation' do |sp|
    sp.ios.vendored_frameworks     = "Carthage/iOS/VSCFoundation.framework"
    sp.osx.vendored_frameworks     = "Carthage/macOS/VSCFoundation.framework"
    sp.tvos.vendored_frameworks    = "Carthage/tvOS/VSCFoundation.framework"
    sp.watchos.vendored_frameworks = "Carthage/watchOS/VSCFoundation.framework"
  end

  s.subspec 'Pythia' do |sp|
    sp.ios.vendored_frameworks     = "Carthage/iOS/VSCPythia.framework"
    sp.osx.vendored_frameworks     = "Carthage/macOS/VSCPythia.framework"
    sp.tvos.vendored_frameworks    = "Carthage/tvOS/VSCPythia.framework"
    sp.watchos.vendored_frameworks = "Carthage/watchOS/VSCPythia.framework"
  end

  s.subspec 'Ratchet' do |sp|
    sp.ios.vendored_frameworks     = "Carthage/iOS/VSCRatchet.framework"
    sp.osx.vendored_frameworks     = "Carthage/macOS/VSCRatchet.framework"
    sp.tvos.vendored_frameworks    = "Carthage/tvOS/VSCRatchet.framework"
    sp.watchos.vendored_frameworks = "Carthage/watchOS/VSCRatchet.framework"
  end
end
