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
        let hash = Sha224.hash(data: "".data(using: .utf8)!)
        XCTAssert("0UoCjCo6K8lHYQK7KII0xBWisB+CjqYqxbPkLw==" == hash.base64EncodedString())
    }

    func test_Sha256_hash_emptyString_success() {
        let hash = Sha256.hash(data: "".data(using: .utf8)!)
        XCTAssert("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=" == hash.base64EncodedString())
    }
}
