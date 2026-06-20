//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2026 Virgil Security, Inc.
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
        hkdf.reset(salt: "".data(using: .utf8)!, iterationCount: 0)
        let key = hkdf.derive(data: "".data(using: .utf8)!, keyLen: 10)
        XCTAssert(key.count == 10)
    }

    private func shamirSecret() -> Data {
        return Data([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0])
    }

    private func selectShares(_ shares: Data, count: Int, _ indices: [Int]) -> Data {
        let shareSize = shares.count / count
        var selection = Data()
        for idx in indices {
            selection.append(shares.subdata(in: (idx * shareSize)..<((idx + 1) * shareSize)))
        }
        return selection
    }

    func test_Shamir_splitCombine_2of3_everyPairRecovers() {
        let shamir = Shamir()
        try! shamir.setupDefaults()
        let secret = shamirSecret()
        let shares = try! shamir.split(secret: secret, threshold: 2, shareCount: 3)

        for pair in [[0, 1], [0, 2], [1, 2], [2, 0]] {
            let recovered = try! shamir.combine(shares: selectShares(shares, count: 3, pair), shareCount: 2)
            XCTAssertEqual(secret, recovered)
        }
    }

    func test_Shamir_splitCombine_generalKofN_recovers() {
        let shamir = Shamir()
        try! shamir.setupDefaults()
        let secret = shamirSecret()
        let shares = try! shamir.split(secret: secret, threshold: 5, shareCount: 7)

        let recovered = try! shamir.combine(shares: selectShares(shares, count: 7, [6, 4, 2, 1, 0]), shareCount: 5)
        XCTAssertEqual(secret, recovered)
    }

    func test_Shamir_combine_insufficientShares_throws() {
        let shamir = Shamir()
        try! shamir.setupDefaults()
        let shares = try! shamir.split(secret: shamirSecret(), threshold: 3, shareCount: 5)

        XCTAssertThrowsError(try shamir.combine(shares: selectShares(shares, count: 5, [0, 1]), shareCount: 2))
    }

    func test_Shamir_combine_duplicateShare_throws() {
        let shamir = Shamir()
        try! shamir.setupDefaults()
        let shares = try! shamir.split(secret: shamirSecret(), threshold: 2, shareCount: 3)

        XCTAssertThrowsError(try shamir.combine(shares: selectShares(shares, count: 3, [1, 1]), shareCount: 2))
    }

    func test_Shamir_combine_tamperedShare_throws() {
        let shamir = Shamir()
        try! shamir.setupDefaults()
        var shares = try! shamir.split(secret: shamirSecret(), threshold: 2, shareCount: 3)

        // Flip a ciphertext byte (offset 68 = envelope header length) of share 0.
        shares[68] ^= 0x01
        XCTAssertThrowsError(try shamir.combine(shares: selectShares(shares, count: 3, [0, 1]), shareCount: 2))
    }

    func test_Shamir_split_invalidThreshold_throws() {
        let shamir = Shamir()
        try! shamir.setupDefaults()
        XCTAssertThrowsError(try shamir.split(secret: shamirSecret(), threshold: 4, shareCount: 3))
    }
}
