// swift-tools-version:5.3

import PackageDescription

let version = "0.16.4-dev1"
let vscCommonChecksum = "252a9b193b25c51548efaabbe3148ec04f3de9263ad3638a389ad7b80c286749"
let vscFoundationChecksum = "13949b968a31750df93529cb0eae01f73130d505ff39ffbf8d922830254dd52e"
let vscPythiaChecksum = "fcc3b4d25987ac7f872b97c3dadd2f581f3f13d151cc87f03537ee110435634b"
let vscRatchetChecksum = "eecb39849af75983b04234c7424a828e33f332be62a87f160d8ab3380193c963"
let package = Package(
    name: "VirgilCryptoWrapper",
    platforms: [
        .macOS(.v10_10), .iOS(.v11), .tvOS(.v11), .watchOS(.v4)
    ],
    products: [
        .library(
            name: "VirgilCryptoFoundation",
            targets: ["VirgilCryptoFoundation"]),

        .library(
            name: "VirgilCryptoPythia",
            targets: ["VirgilCryptoPythia"]),

        .library(
            name: "VirgilCryptoRatchet",
            targets: ["VirgilCryptoRatchet"]),

    ],
    targets: [
        //
        // VSCCrypto
        //
        .binaryTarget(
            name: "VSCCommon",
            url: "https://github.com/VirgilSecurity/virgil-crypto-c/releases/download/v\(version)/VSCCommon.xcframework.zip",
            checksum: vscCommonChecksum
        ),

        .binaryTarget(
            name: "VSCFoundation",
            url: "https://github.com/VirgilSecurity/virgil-crypto-c/releases/download/v\(version)/VSCFoundation.xcframework.zip",
            checksum: vscFoundationChecksum
        ),

        .binaryTarget(
            name: "VSCPythia",
            url: "https://github.com/VirgilSecurity/virgil-crypto-c/releases/download/v\(version)/VSCPythia.xcframework.zip",
            checksum: vscPythiaChecksum
        ),

        .binaryTarget(
            name: "VSCRatchet",
            url: "https://github.com/VirgilSecurity/virgil-crypto-c/releases/download/v\(version)/VSCRatchet.xcframework.zip",
            checksum: vscRatchetChecksum
        ),

        //
        // VirgilCryptoFoundation
        //
        .target(
            name: "VirgilCryptoFoundation",
            dependencies: ["VSCCommon", "VSCFoundation"],
            path: "wrappers/swift/VirgilCrypto/VirgilCryptoFoundation"),

        .testTarget(
            name: "VirgilCryptoFoundationTests",
            dependencies: ["VirgilCryptoFoundation"],
            path: "wrappers/swift/VirgilCryptoTest/VirgilCryptoFoundationTests"),

        //
        // VirgilCryptoPythia
        //
        .target(
            name: "VirgilCryptoPythia",
            dependencies: ["VirgilCryptoFoundation", "VSCPythia"],
            path: "wrappers/swift/VirgilCrypto/VirgilCryptoPythia"),

        .testTarget(
            name: "VirgilCryptoPythiaTests",
            dependencies: ["VirgilCryptoPythia"],
            path: "wrappers/swift/VirgilCryptoTest/VirgilCryptoPythiaTests"),

        //
        // VirgilCryptoRatchet
        //
        .target(
            name: "VirgilCryptoRatchet",
            dependencies: ["VirgilCryptoFoundation", "VSCRatchet"],
            path: "wrappers/swift/VirgilCrypto/VirgilCryptoRatchet"),

        .testTarget(
            name: "VirgilCryptoRatchetTests",
            dependencies: ["VirgilCryptoRatchet"],
            path: "wrappers/swift/VirgilCryptoTest/VirgilCryptoRatchetTests"),
    ]
)
