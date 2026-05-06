// swift-tools-version:5.3

import PackageDescription

let version = "0.18.0-dev.3"
let useLocalBinaries = false

let vscCommonBinaryTarget = {
    if (useLocalBinaries) {
        return Target.binaryTarget(name: "VSCCommon", path: "binaries//VSCCommon.xcframework.zip")
    } else {
        let vscCommonChecksum = "1f00f0ba9135a7db7399a458445879563a76c6fcfe66fb5a01395180845c5e26"
        return Target.binaryTarget(
            name: "VSCCommon",
            url: "https://github.com/VirgilSecurity/virgil-crypto-c/releases/download/v\(version)/VSCCommon.xcframework.zip",
            checksum: vscCommonChecksum
        )
    }
}()

let vscFoundationBinaryTarget = {
    if (useLocalBinaries) {
        return Target.binaryTarget(name: "VSCFoundation", path: "binaries//VSCFoundation.xcframework.zip")
    } else {
        let vscFoundationChecksum = "d06e9995625d8575e7d702909e86c5417ae92aff30771921bddcb8d445a573f7"
        return Target.binaryTarget(
            name: "VSCFoundation",
            url: "https://github.com/VirgilSecurity/virgil-crypto-c/releases/download/v\(version)/VSCFoundation.xcframework.zip",
            checksum: vscFoundationChecksum
        )
    }
}()

let vscPythiaBinaryTarget = {
    if (useLocalBinaries) {
        return Target.binaryTarget(name: "VSCPythia", path: "binaries//VSCPythia.xcframework.zip")
    } else {
        let vscPythiaChecksum = "365d761e33ca04b72cc8f3b81772b4c1191a56bb14ec2c4a0f9ddbaeb426cd67"
        return Target.binaryTarget(
            name: "VSCPythia",
            url: "https://github.com/VirgilSecurity/virgil-crypto-c/releases/download/v\(version)/VSCPythia.xcframework.zip",
            checksum: vscPythiaChecksum
        )
    }
}()

let vscRatchetBinaryTarget = {
    if (useLocalBinaries) {
        return Target.binaryTarget(name: "VSCRatchet", path: "binaries//VSCRatchet.xcframework.zip")
    } else {
        let vscRatchetChecksum = "99c46de3a54cfbb1d8651f8390be16a1a9a56003139e65d4898c8242fe271325"
        return Target.binaryTarget(
            name: "VSCRatchet",
            url: "https://github.com/VirgilSecurity/virgil-crypto-c/releases/download/v\(version)/VSCRatchet.xcframework.zip",
            checksum: vscRatchetChecksum
        )
    }
}()



let package = Package(
    name: "VirgilCryptoWrapper",
    platforms: [
        .macOS(.v10_13), .iOS(.v11), .tvOS(.v11), .watchOS(.v4)
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
        vscCommonBinaryTarget,
        vscFoundationBinaryTarget,
        vscPythiaBinaryTarget,
        vscRatchetBinaryTarget,

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
