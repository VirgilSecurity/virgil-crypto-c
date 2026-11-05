// swift-tools-version:5.3

import PackageDescription

let version = "0.23.2"
let useLocalBinaries = false

let vscCommonBinaryTarget = {
    if (useLocalBinaries) {
        return Target.binaryTarget(name: "VSCCommon", path: "binaries//VSCCommon.xcframework.zip")
    } else {
        let vscCommonChecksum = "04f5160ab9235645d280050f018436a63cc33b92b53cf05a1ccc5c1c6f96aff8"
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
        let vscFoundationChecksum = "da24d41ed5a37869764e87e4723fb270110d46189f1a26ff2fdc2413281d93c6"
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
        let vscRatchetChecksum = "269227341a0c0f8c93ec454d3be7b981a6fe71a6e9d47f4a56724642002e0f07"
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
