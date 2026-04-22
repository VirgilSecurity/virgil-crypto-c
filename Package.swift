// swift-tools-version:5.3

import PackageDescription

let version = "0.18.0-dev.3"
let useLocalBinaries = false

let vscCommonBinaryTarget = {
    if (useLocalBinaries) {
        return Target.binaryTarget(name: "VSCCommon", path: "binaries//VSCCommon.xcframework.zip")
    } else {
        let vscCommonChecksum = "1c2d9902195e94ccdfce78afa2e3452de80e50f27527d26a296188b169c10d94"
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
        let vscFoundationChecksum = "b4a4157cad3eaa2f287a4b440f2eb5540d4292aad546f7bd7c8c9e56a6273feb"
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
        let vscPythiaChecksum = "a90c944158922189f0d179b329e53d1d6797778ffb8fc02008c5d37fed7abc6c"
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
        let vscRatchetChecksum = "ca67d245f91aade959437ba037a3ff57c4b75717531138d0b24740fe658506d0"
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
