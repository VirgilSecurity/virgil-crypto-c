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

    func initializeRatchet (alice ratchetAlice: Ratchet, bob ratchetBob: Ratchet) {
        let kdfInfo = RatchetKdfInfo()
        
        ratchetAlice.setKdfInfo(kdfInfo: kdfInfo)
    }
    
    func test_ErrorCtx_callDefaultInit_success() {
        let ratchetAlice = Ratchet()
        let ratchetBob = Ratchet()
        
        initializeRatchet(alice: ratchetAlice, bob: ratchetBob)
    }
}
