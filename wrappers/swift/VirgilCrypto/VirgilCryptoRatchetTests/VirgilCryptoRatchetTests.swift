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
@testable import VirgilCryptoRatchet

class VirgilCryptoRatchetTests: XCTestCase {

    func initializeRatchet (alice ratchetAlice: Ratchet, bob ratchetBob: Ratchet) throws {
        let kdfInfo = RatchetKdfInfo(rootInfo: "some root info".data(using: .utf8)!, ratchetInfo: "some ratchet info".data(using: .utf8)!)
        let ratchetCipher = RatchetCipher(kdfInfo: "kdf info".data(using: .utf8)!)

        ratchetAlice.setCipher(cipher: ratchetCipher)
        ratchetBob.setCipher(cipher: ratchetCipher)
        ratchetAlice.setKdfInfo(kdfInfo: kdfInfo)
        ratchetBob.setKdfInfo(kdfInfo: kdfInfo)
        ratchetAlice.setRng(rng: VirgilRatchetFakeRng())
        ratchetBob.setRng(rng: VirgilRatchetFakeRng())

        let publicKey = Data(base64Encoded: "6so4kbNJrxFBkP4Svar21KeI/2gGst5SRZMP2OTq9mo=")!
        let privateKey = Data(base64Encoded: "Y8SLROj5RhaoOIlbf7eHGwN4/aPNtw8/P5gZmg7DXE8=")!
        let sharedKey = Data(base64Encoded: "m1u49Su5QkF/LU9cbub60gfup6SuZs3vk9+0GIGfZHGPDWxx+0N6PTWb97d0QerQortAfkc5KlXGu1NdHKZusnu76n8QGv4Jt6GMK9vy7+KqkKhF2Nxd3g/ajbd67cg8")!

        try ratchetAlice.initiate(sharedSecret: sharedKey, ratchetPrivateKey: privateKey)
        ratchetBob.respond(sharedSecret: sharedKey, ratchetPublicKey: publicKey)
    }

    func test_ErrorCtx_callDefaultInit_success() {
        let ratchetAlice = Ratchet()
        let ratchetBob = Ratchet()

        try! initializeRatchet(alice: ratchetAlice, bob: ratchetBob)

        let plainText = "hello"
        let cipherText = try! ratchetAlice.encrypt(plainText: plainText.data(using: .utf8)!)

        let decryptedData = try! ratchetBob.decrypt(cipherText: cipherText)
        let decryptedText = String(data: decryptedData, encoding: .utf8)!

        XCTAssertEqual(plainText, decryptedText)
    }
}
