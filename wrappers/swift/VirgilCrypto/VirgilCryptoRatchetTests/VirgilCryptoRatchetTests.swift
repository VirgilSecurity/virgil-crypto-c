//
//  VirgilCryptoRatchetTests.swift
//  VirgilCryptoRatchetTests
//
//  Created by Sergey Seroshtan on 10/26/18.
//  Copyright © 2018 Virgil Security, Inc. All rights reserved.
//

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
