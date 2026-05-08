// swift-tools-version:5.3

import PackageDescription

let version = "0.19.0-dev.3"
let useLocalBinaries = false

let vscCommonBinaryTarget = {
    if (useLocalBinaries) {
        return Target.binaryTarget(name: "VSCCommon", path: "binaries//VSCCommon.xcframework.zip")
    } else {
        let vscCommonChecksum = "e5f62d62f2219dd98f417c1030663d92586ada3eff5c6b83acebdbbb633c0d24"
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
        let vscFoundationChecksum = "9f0b85fefc2062acc4d1eb554c70bd444bf106359919489025dc7c6e134251c0"
        return Target.binaryTarget(
            name: "VSCFoundation",
            url: "https://github.com/VirgilSecurity/virgil-crypto-c/releases/download/v\(version)/VSCFoundation.xcframework.zip",
            checksum: vscFoundationChecksum
        )
    }
}()

let vscRatchetBinaryTarget = {
    if (useLocalBinaries) {
        return Target.binaryTarget(name: "VSCRatchet", path: "binaries//VSCRatchet.xcframework.zip")
    } else {
        let vscRatchetChecksum = "c6e33a24fb044d2b433a1dc684e67f96d14b614364106d4e5afad1b54156295e"
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
            name: "VirgilCryptoRatchet",
            targets: ["VirgilCryptoRatchet"]),

    ],
    targets: [
        //
        // VSCCrypto
        //
        vscCommonBinaryTarget,
        vscFoundationBinaryTarget,
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
