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

/// Provide Pythia implementation based on the Virgil Security.
@objc(VSCPPythia) public class Pythia {
    @objc func public static init() {
        //  TODO: Implement me.
    }
    @objc func public static cleanup() {
        //  TODO: Implement me.
    }
    @objc func public static blindedPasswordBufLen() -> Int {
        //  TODO: Implement me.
    }
    @objc func public static deblindedPasswordBufLen() -> Int {
        //  TODO: Implement me.
    }
    @objc func public static blindingSecretBufLen() -> Int {
        //  TODO: Implement me.
    }
    @objc func public static transformationPrivateKeyBufLen() -> Int {
        //  TODO: Implement me.
    }
    @objc func public static transformationPublicKeyBufLen() -> Int {
        //  TODO: Implement me.
    }
    @objc func public static transformedPasswordBufLen() -> Int {
        //  TODO: Implement me.
    }
    @objc func public static transformedTweakBufLen() -> Int {
        //  TODO: Implement me.
    }
    @objc func public static proofValueBufLen() -> Int {
        //  TODO: Implement me.
    }
    @objc func public static passwordUpdateTokenBufLen() -> Int {
        //  TODO: Implement me.
    }
    @objc func public blind(password: Data) throws -> (blindedPassword: Data, blindingSecret: Data) {
        //  TODO: Implement me.
    }
    @objc func public deblind(transformedPassword: Data, blindingSecret: Data) throws -> Data {
        //  TODO: Implement me.
    }
    @objc func public computeTransformationKeyPair(transformationKeyId: Data, pythiaSecret: Data, pythiaScopeSecret: Data) throws -> (transformationPrivateKey: Data, transformationPublicKey: Data) {
        //  TODO: Implement me.
    }
    @objc func public transform(blindedPassword: Data, tweak: Data, transformationPrivateKey: Data) throws -> (transformedPassword: Data, transformedTweak: Data) {
        //  TODO: Implement me.
    }
    @objc func public prove(transformedPassword: Data, blindedPassword: Data, transformedTweak: Data, transformationPrivateKey: Data, transformationPublicKey: Data) throws -> (proofValueC: Data, proofValueU: Data) {
        //  TODO: Implement me.
    }
    @objc func public verify(transformedPassword: Data, blindedPassword: Data, tweak: Data, transformationPublicKey: Data, proofValueC: Data, proofValueU: Data) throws {
        //  TODO: Implement me.
    }
    @objc func public getPasswordUpdateToken(previousTransformationPrivateKey: Data, newTransformationPrivateKey: Data) throws -> Data {
        //  TODO: Implement me.
    }
    @objc func public updateDeblindedWithToken(deblindedPassword: Data, passwordUpdateToken: Data) throws -> Data {
        //  TODO: Implement me.
    }
}

