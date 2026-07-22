// swift-tools-version:5.3

import PackageDescription

let version = "0.23.0"
let useLocalBinaries = false

let vscCommonBinaryTarget = {
    if (useLocalBinaries) {
        return Target.binaryTarget(name: "VSCCommon", path: "binaries//VSCCommon.xcframework.zip")
    } else {
        let vscCommonChecksum = "9c1bd65602901ca692a04c8ffa548077649104c4988301418ddb6fbdcf709f79"
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
        let vscFoundationChecksum = "70b43d5b76a85aa6131c61e6622c8003778a6cb994be388dc7720bfeaea18b66"
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
        let vscRatchetChecksum = "87be1200df04fbd1a3bd63790265f5536f435fcde6004a36eaf4ee78f02f329d"
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
