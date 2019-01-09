//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
// --------------------------------------------------------------------------
//  @end

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
