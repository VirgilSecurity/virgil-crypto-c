//
//  VirgilCryptoPythiaTests.swift
//  VirgilCryptoPythiaTests
//
//  Created by Sergey Seroshtan on 10/14/18.
//  Copyright © 2018 Virgil Security, Inc. All rights reserved.
//

import XCTest
@testable import VirgilCryptoPythia

class VirgilCryptoPythiaTests: XCTestCase {

    override func setUp() {
        Pythia.globalInit()
    }

    override func tearDown() {
        Pythia.globalCleanup()
    }

    func testBlind() {
        let pythia = Pythia()
        let result = try! pythia.blind(password: "password".data(using: .utf8)!)
        XCTAssert(result.blindedPassword.count == Pythia.blindedPasswordBufLen())
    }

}
