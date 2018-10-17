/// Copyright (C) 2015-2018 Virgil Security Inc.
///
/// All rights reserved.
///
/// Redistribution and use in source and binary forms, with or without
/// modification, are permitted provided that the following conditions are
/// met:
///
///     (1) Redistributions of source code must retain the above copyright
///     notice, this list of conditions and the following disclaimer.
///
///     (2) Redistributions in binary form must reproduce the above copyright
///     notice, this list of conditions and the following disclaimer in
///     the documentation and/or other materials provided with the
///     distribution.
///
///     (3) Neither the name of the copyright holder nor the names of its
///     contributors may be used to endorse or promote products derived from
///     this software without specific prior written permission.
///
/// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
/// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
/// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
/// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
/// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
/// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
/// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
/// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
/// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
/// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
/// POSSIBILITY OF SUCH DAMAGE.
///
/// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>


import Foundation
import VSCPythia

/// Provide Pythia implementation based on the Virgil Security.
@objc(VSCPPythia) public class Pythia : NSObject {
    private var c_ctx: UnsafeMutablePointer<vscp_pythia_t>

    public override init() {
        self.c_ctx = vscp_pythia_new()
    }

    deinit {
        vscp_pythia_delete(self.c_ctx)
    }

    @objc public static func globalInit() {
        vscp_global_init()
    }

    @objc public static func globalCleanup() {
        vscp_global_cleanup()
    }

    @objc public static func blindedPasswordBufLen() -> Int {
        return vscp_pythia_blinded_password_buf_len()
    }

    @objc public static func deblindedPasswordBufLen() -> Int {
        return vscp_pythia_blinded_password_buf_len()
    }

    @objc public static func blindingSecretBufLen() -> Int {
        return vscp_pythia_blinding_secret_buf_len()
    }

    @objc public static func transformationPrivateKeyBufLen() -> Int {
        return vscp_pythia_transformation_private_key_buf_len()
    }

    @objc public static func transformationPublicKeyBufLen() -> Int {
        return vscp_pythia_transformation_public_key_buf_len()
    }

    @objc public static func transformedPasswordBufLen() -> Int {
        return vscp_pythia_transformed_password_buf_len()
    }

    @objc public static func transformedTweakBufLen() -> Int {
        return vscp_pythia_transformed_tweak_buf_len()
    }

    @objc public static func proofValueBufLen() -> Int {
        return vscp_pythia_proof_value_buf_len()
    }

    @objc public static func passwordUpdateTokenBufLen() -> Int {
        return vscp_pythia_password_update_token_buf_len()
    }

    @objc public func blind(password: Data) throws -> PythiaBlindResult {

        let blindedPasswordCount = Pythia.blindedPasswordBufLen()
        var blindedPassword = Data(count: blindedPasswordCount)
        
        let blindingSecretCount = Pythia.blindingSecretBufLen()
        var blindingSecret = Data(count: blindingSecretCount)

        var blindedPasswordBuf = vsc_buffer_t()
        var blindingSecretBuf = vsc_buffer_t()

        let error = password.withUnsafeBytes ({ (passwordPointer: UnsafePointer<byte>) -> vscp_error_t in
            blindedPassword.withUnsafeMutableBytes({ (blindedPasswordPointer: UnsafeMutablePointer<byte>) -> vscp_error_t in
                blindingSecret.withUnsafeMutableBytes({ (blindingSecretPointer: UnsafeMutablePointer<byte>) -> vscp_error_t in
                    vsc_buffer_init(&blindedPasswordBuf)
                    vsc_buffer_use(&blindedPasswordBuf, blindedPasswordPointer, blindedPasswordCount)
                    
                    vsc_buffer_init(&blindingSecretBuf)
                    vsc_buffer_use(&blindingSecretBuf, blindingSecretPointer, blindingSecretCount)
                    
                    return vscp_pythia_blind(c_ctx, vsc_data(passwordPointer, password.count), &blindedPasswordBuf, &blindingSecretBuf)
                })
            })
        })
        
        blindedPassword.count = vsc_buffer_len(&blindedPasswordBuf)
        blindingSecret.count = vsc_buffer_len(&blindingSecretBuf)
        
        try! PythiaError.handleError(fromC: error)
        
        return PythiaBlindResult.init(blindedPassword: blindedPassword, blindingSecret: blindingSecret)
    }

    @objc public func deblind(transformedPassword: Data, blindingSecret: Data) throws -> Data {

        throw NSError()
    }

    @objc public func computeTransformationKeyPair(transformationKeyId: Data, pythiaSecret: Data, pythiaScopeSecret: Data) throws -> PythiaComputeTransformationKeyPairResult {

        throw NSError()
    }

    @objc public func transform(blindedPassword: Data, tweak: Data, transformationPrivateKey: Data) throws -> PythiaTransformResult {

        throw NSError()
    }

    @objc public func prove(transformedPassword: Data, blindedPassword: Data, transformedTweak: Data, transformationPrivateKey: Data, transformationPublicKey: Data) throws -> PythiaProveResult {

        throw NSError()
    }

    @objc public func verify(transformedPassword: Data, blindedPassword: Data, tweak: Data, transformationPublicKey: Data, proofValueC: Data, proofValueU: Data) throws {

        throw NSError()
    }

    @objc public func getPasswordUpdateToken(previousTransformationPrivateKey: Data, newTransformationPrivateKey: Data) throws -> Data {

        throw NSError()
    }

    @objc public func updateDeblindedWithToken(deblindedPassword: Data, passwordUpdateToken: Data) throws -> Data {

        throw NSError()
    }
}

/// Encapsulate result of method Pythia.blind()
@objc(VSCPPythiaBlindResult) public class PythiaBlindResult : NSObject {
    @objc public let blindedPassword: Data
    @objc public let blindingSecret: Data

    internal init(blindedPassword: Data, blindingSecret: Data) {
        self.blindedPassword = blindedPassword
        self.blindingSecret = blindingSecret
        
        super.init()
    }
}

/// Encapsulate result of method Pythia.computeTransformationKeyPair()
@objc(VSCPPythiaComputeTransformationKeyPairResult) public class PythiaComputeTransformationKeyPairResult : NSObject {
}

/// Encapsulate result of method Pythia.transform()
@objc(VSCPPythiaTransformResult) public class PythiaTransformResult : NSObject {
}

/// Encapsulate result of method Pythia.prove()
@objc(VSCPPythiaProveResult) public class PythiaProveResult : NSObject {
}

