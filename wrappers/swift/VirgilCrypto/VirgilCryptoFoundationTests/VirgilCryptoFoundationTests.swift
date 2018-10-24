//
//  VirgilCryptoFoundationTests.swift
//  VirgilCryptoFoundationTests
//
//  Created by Sergey Seroshtan on 10/14/18.
//  Copyright © 2018 Virgil Security, Inc. All rights reserved.
//

import XCTest
@testable import VirgilCryptoFoundation

class VirgilCryptoFoundationTests: XCTestCase {

    func test_Sha224_hash_emptyString_success() {
        let hash = Sha224().hash(data: "".data(using: .utf8)!)
        XCTAssert("0UoCjCo6K8lHYQK7KII0xBWisB+CjqYqxbPkLw==" == hash.base64EncodedString())
    }

    func test_Sha256_hash_emptyString_success() {
        let hash = Sha256().hash(data: "".data(using: .utf8)!)
        XCTAssert("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=" == hash.base64EncodedString())
    }

    func test_Sha512_hash_helloString_success() {
        let hash = Sha512().hash(data: "hello".data(using: .utf8)!)
        XCTAssert("m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRlnPKcjI8PZm6XBHXx6zG4UuMXaDEZjR1wuXDre9G9zvN7AQw==" == hash.base64EncodedString())
    }
    
    func test_Hkdf_derive_emptyString_success() {
        let hkdf = Hkdf()
        hkdf.setHash(hash: Sha256())
        let key = hkdf.derive(data: "".data(using: .utf8)!, salt: "".data(using: .utf8)!, info: "".data(using: .utf8)!, keyLen: 10)
        XCTAssert(key.count == 10)
    }
}
