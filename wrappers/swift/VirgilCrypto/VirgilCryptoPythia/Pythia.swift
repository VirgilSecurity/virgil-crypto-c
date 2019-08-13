/// Copyright (C) 2015-2019 Virgil Security, Inc.
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
@objc(VSCPPythia) public class Pythia: NSObject {

    /// Performs global initialization of the pythia library.
    /// Must be called once for entire application at startup.
    @objc public static func configure() throws {
        let proxyResult = vscp_pythia_configure()

        try PythiaError.handleStatus(fromC: proxyResult)
    }

    /// Performs global cleanup of the pythia library.
    /// Must be called once for entire application before exit.
    @objc public static func cleanup() {
        vscp_pythia_cleanup()
    }

    /// Return length of the buffer needed to hold 'blinded password'.
    @objc public static func blindedPasswordBufLen() -> Int {
        let proxyResult = vscp_pythia_blinded_password_buf_len()

        return proxyResult
    }

    /// Return length of the buffer needed to hold 'deblinded password'.
    @objc public static func deblindedPasswordBufLen() -> Int {
        let proxyResult = vscp_pythia_deblinded_password_buf_len()

        return proxyResult
    }

    /// Return length of the buffer needed to hold 'blinding secret'.
    @objc public static func blindingSecretBufLen() -> Int {
        let proxyResult = vscp_pythia_blinding_secret_buf_len()

        return proxyResult
    }

    /// Return length of the buffer needed to hold 'transformation private key'.
    @objc public static func transformationPrivateKeyBufLen() -> Int {
        let proxyResult = vscp_pythia_transformation_private_key_buf_len()

        return proxyResult
    }

    /// Return length of the buffer needed to hold 'transformation public key'.
    @objc public static func transformationPublicKeyBufLen() -> Int {
        let proxyResult = vscp_pythia_transformation_public_key_buf_len()

        return proxyResult
    }

    /// Return length of the buffer needed to hold 'transformed password'.
    @objc public static func transformedPasswordBufLen() -> Int {
        let proxyResult = vscp_pythia_transformed_password_buf_len()

        return proxyResult
    }

    /// Return length of the buffer needed to hold 'transformed tweak'.
    @objc public static func transformedTweakBufLen() -> Int {
        let proxyResult = vscp_pythia_transformed_tweak_buf_len()

        return proxyResult
    }

    /// Return length of the buffer needed to hold 'proof value'.
    @objc public static func proofValueBufLen() -> Int {
        let proxyResult = vscp_pythia_proof_value_buf_len()

        return proxyResult
    }

    /// Return length of the buffer needed to hold 'password update token'.
    @objc public static func passwordUpdateTokenBufLen() -> Int {
        let proxyResult = vscp_pythia_password_update_token_buf_len()

        return proxyResult
    }

    /// Blinds password. Turns password into a pseudo-random string.
    /// This step is necessary to prevent 3rd-parties from knowledge of end user's password.
    @objc public static func blind(password: Data) throws -> PythiaBlindResult {
        let blindedPasswordCount = Pythia.blindedPasswordBufLen()
        var blindedPassword = Data(count: blindedPasswordCount)
        var blindedPasswordBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(blindedPasswordBuf)
        }

        let blindingSecretCount = Pythia.blindingSecretBufLen()
        var blindingSecret = Data(count: blindingSecretCount)
        var blindingSecretBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(blindingSecretBuf)
        }

        let proxyResult = password.withUnsafeBytes({ (passwordPointer: UnsafeRawBufferPointer) -> vscp_status_t in
            blindedPassword.withUnsafeMutableBytes({ (blindedPasswordPointer: UnsafeMutableRawBufferPointer) -> vscp_status_t in
                blindingSecret.withUnsafeMutableBytes({ (blindingSecretPointer: UnsafeMutableRawBufferPointer) -> vscp_status_t in
                    vsc_buffer_init(blindedPasswordBuf)
                    vsc_buffer_use(blindedPasswordBuf, blindedPasswordPointer.bindMemory(to: byte.self).baseAddress, blindedPasswordCount)

                    vsc_buffer_init(blindingSecretBuf)
                    vsc_buffer_use(blindingSecretBuf, blindingSecretPointer.bindMemory(to: byte.self).baseAddress, blindingSecretCount)

                    return vscp_pythia_blind(vsc_data(passwordPointer.bindMemory(to: byte.self).baseAddress, password.count), blindedPasswordBuf, blindingSecretBuf)
                })
            })
        })
        blindedPassword.count = vsc_buffer_len(blindedPasswordBuf)
        blindingSecret.count = vsc_buffer_len(blindingSecretBuf)

        try PythiaError.handleStatus(fromC: proxyResult)

        return PythiaBlindResult(blindedPassword: blindedPassword, blindingSecret: blindingSecret)
    }

    /// Deblinds 'transformed password' value with previously returned 'blinding secret' from blind().
    @objc public static func deblind(transformedPassword: Data, blindingSecret: Data) throws -> Data {
        let deblindedPasswordCount = Pythia.deblindedPasswordBufLen()
        var deblindedPassword = Data(count: deblindedPasswordCount)
        var deblindedPasswordBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(deblindedPasswordBuf)
        }

        let proxyResult = transformedPassword.withUnsafeBytes({ (transformedPasswordPointer: UnsafeRawBufferPointer) -> vscp_status_t in
            blindingSecret.withUnsafeBytes({ (blindingSecretPointer: UnsafeRawBufferPointer) -> vscp_status_t in
                deblindedPassword.withUnsafeMutableBytes({ (deblindedPasswordPointer: UnsafeMutableRawBufferPointer) -> vscp_status_t in
                    vsc_buffer_init(deblindedPasswordBuf)
                    vsc_buffer_use(deblindedPasswordBuf, deblindedPasswordPointer.bindMemory(to: byte.self).baseAddress, deblindedPasswordCount)

                    return vscp_pythia_deblind(vsc_data(transformedPasswordPointer.bindMemory(to: byte.self).baseAddress, transformedPassword.count), vsc_data(blindingSecretPointer.bindMemory(to: byte.self).baseAddress, blindingSecret.count), deblindedPasswordBuf)
                })
            })
        })
        deblindedPassword.count = vsc_buffer_len(deblindedPasswordBuf)

        try PythiaError.handleStatus(fromC: proxyResult)

        return deblindedPassword
    }

    /// Computes transformation private and public key.
    @objc public static func computeTransformationKeyPair(transformationKeyId: Data, pythiaSecret: Data, pythiaScopeSecret: Data) throws -> PythiaComputeTransformationKeyPairResult {
        let transformationPrivateKeyCount = Pythia.transformationPrivateKeyBufLen()
        var transformationPrivateKey = Data(count: transformationPrivateKeyCount)
        var transformationPrivateKeyBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(transformationPrivateKeyBuf)
        }

        let transformationPublicKeyCount = Pythia.transformationPublicKeyBufLen()
        var transformationPublicKey = Data(count: transformationPublicKeyCount)
        var transformationPublicKeyBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(transformationPublicKeyBuf)
        }

        let proxyResult = transformationKeyId.withUnsafeBytes({ (transformationKeyIdPointer: UnsafeRawBufferPointer) -> vscp_status_t in
            pythiaSecret.withUnsafeBytes({ (pythiaSecretPointer: UnsafeRawBufferPointer) -> vscp_status_t in
                pythiaScopeSecret.withUnsafeBytes({ (pythiaScopeSecretPointer: UnsafeRawBufferPointer) -> vscp_status_t in
                    transformationPrivateKey.withUnsafeMutableBytes({ (transformationPrivateKeyPointer: UnsafeMutableRawBufferPointer) -> vscp_status_t in
                        transformationPublicKey.withUnsafeMutableBytes({ (transformationPublicKeyPointer: UnsafeMutableRawBufferPointer) -> vscp_status_t in
                            vsc_buffer_init(transformationPrivateKeyBuf)
                            vsc_buffer_use(transformationPrivateKeyBuf, transformationPrivateKeyPointer.bindMemory(to: byte.self).baseAddress, transformationPrivateKeyCount)

                            vsc_buffer_init(transformationPublicKeyBuf)
                            vsc_buffer_use(transformationPublicKeyBuf, transformationPublicKeyPointer.bindMemory(to: byte.self).baseAddress, transformationPublicKeyCount)

                            return vscp_pythia_compute_transformation_key_pair(vsc_data(transformationKeyIdPointer.bindMemory(to: byte.self).baseAddress, transformationKeyId.count), vsc_data(pythiaSecretPointer.bindMemory(to: byte.self).baseAddress, pythiaSecret.count), vsc_data(pythiaScopeSecretPointer.bindMemory(to: byte.self).baseAddress, pythiaScopeSecret.count), transformationPrivateKeyBuf, transformationPublicKeyBuf)
                        })
                    })
                })
            })
        })
        transformationPrivateKey.count = vsc_buffer_len(transformationPrivateKeyBuf)
        transformationPublicKey.count = vsc_buffer_len(transformationPublicKeyBuf)

        try PythiaError.handleStatus(fromC: proxyResult)

        return PythiaComputeTransformationKeyPairResult(transformationPrivateKey: transformationPrivateKey, transformationPublicKey: transformationPublicKey)
    }

    /// Transforms blinded password using transformation private key.
    @objc public static func transform(blindedPassword: Data, tweak: Data, transformationPrivateKey: Data) throws -> PythiaTransformResult {
        let transformedPasswordCount = Pythia.transformedPasswordBufLen()
        var transformedPassword = Data(count: transformedPasswordCount)
        var transformedPasswordBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(transformedPasswordBuf)
        }

        let transformedTweakCount = Pythia.transformedTweakBufLen()
        var transformedTweak = Data(count: transformedTweakCount)
        var transformedTweakBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(transformedTweakBuf)
        }

        let proxyResult = blindedPassword.withUnsafeBytes({ (blindedPasswordPointer: UnsafeRawBufferPointer) -> vscp_status_t in
            tweak.withUnsafeBytes({ (tweakPointer: UnsafeRawBufferPointer) -> vscp_status_t in
                transformationPrivateKey.withUnsafeBytes({ (transformationPrivateKeyPointer: UnsafeRawBufferPointer) -> vscp_status_t in
                    transformedPassword.withUnsafeMutableBytes({ (transformedPasswordPointer: UnsafeMutableRawBufferPointer) -> vscp_status_t in
                        transformedTweak.withUnsafeMutableBytes({ (transformedTweakPointer: UnsafeMutableRawBufferPointer) -> vscp_status_t in
                            vsc_buffer_init(transformedPasswordBuf)
                            vsc_buffer_use(transformedPasswordBuf, transformedPasswordPointer.bindMemory(to: byte.self).baseAddress, transformedPasswordCount)

                            vsc_buffer_init(transformedTweakBuf)
                            vsc_buffer_use(transformedTweakBuf, transformedTweakPointer.bindMemory(to: byte.self).baseAddress, transformedTweakCount)

                            return vscp_pythia_transform(vsc_data(blindedPasswordPointer.bindMemory(to: byte.self).baseAddress, blindedPassword.count), vsc_data(tweakPointer.bindMemory(to: byte.self).baseAddress, tweak.count), vsc_data(transformationPrivateKeyPointer.bindMemory(to: byte.self).baseAddress, transformationPrivateKey.count), transformedPasswordBuf, transformedTweakBuf)
                        })
                    })
                })
            })
        })
        transformedPassword.count = vsc_buffer_len(transformedPasswordBuf)
        transformedTweak.count = vsc_buffer_len(transformedTweakBuf)

        try PythiaError.handleStatus(fromC: proxyResult)

        return PythiaTransformResult(transformedPassword: transformedPassword, transformedTweak: transformedTweak)
    }

    /// Generates proof that server possesses secret values that were used to transform password.
    @objc public static func prove(transformedPassword: Data, blindedPassword: Data, transformedTweak: Data, transformationPrivateKey: Data, transformationPublicKey: Data) throws -> PythiaProveResult {
        let proofValueCCount = Pythia.proofValueBufLen()
        var proofValueC = Data(count: proofValueCCount)
        var proofValueCBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(proofValueCBuf)
        }

        let proofValueUCount = Pythia.proofValueBufLen()
        var proofValueU = Data(count: proofValueUCount)
        var proofValueUBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(proofValueUBuf)
        }

        let proxyResult = transformedPassword.withUnsafeBytes({ (transformedPasswordPointer: UnsafeRawBufferPointer) -> vscp_status_t in
            blindedPassword.withUnsafeBytes({ (blindedPasswordPointer: UnsafeRawBufferPointer) -> vscp_status_t in
                transformedTweak.withUnsafeBytes({ (transformedTweakPointer: UnsafeRawBufferPointer) -> vscp_status_t in
                    transformationPrivateKey.withUnsafeBytes({ (transformationPrivateKeyPointer: UnsafeRawBufferPointer) -> vscp_status_t in
                        transformationPublicKey.withUnsafeBytes({ (transformationPublicKeyPointer: UnsafeRawBufferPointer) -> vscp_status_t in
                            proofValueC.withUnsafeMutableBytes({ (proofValueCPointer: UnsafeMutableRawBufferPointer) -> vscp_status_t in
                                proofValueU.withUnsafeMutableBytes({ (proofValueUPointer: UnsafeMutableRawBufferPointer) -> vscp_status_t in
                                    vsc_buffer_init(proofValueCBuf)
                                    vsc_buffer_use(proofValueCBuf, proofValueCPointer.bindMemory(to: byte.self).baseAddress, proofValueCCount)

                                    vsc_buffer_init(proofValueUBuf)
                                    vsc_buffer_use(proofValueUBuf, proofValueUPointer.bindMemory(to: byte.self).baseAddress, proofValueUCount)

                                    return vscp_pythia_prove(vsc_data(transformedPasswordPointer.bindMemory(to: byte.self).baseAddress, transformedPassword.count), vsc_data(blindedPasswordPointer.bindMemory(to: byte.self).baseAddress, blindedPassword.count), vsc_data(transformedTweakPointer.bindMemory(to: byte.self).baseAddress, transformedTweak.count), vsc_data(transformationPrivateKeyPointer.bindMemory(to: byte.self).baseAddress, transformationPrivateKey.count), vsc_data(transformationPublicKeyPointer.bindMemory(to: byte.self).baseAddress, transformationPublicKey.count), proofValueCBuf, proofValueUBuf)
                                })
                            })
                        })
                    })
                })
            })
        })
        proofValueC.count = vsc_buffer_len(proofValueCBuf)
        proofValueU.count = vsc_buffer_len(proofValueUBuf)

        try PythiaError.handleStatus(fromC: proxyResult)

        return PythiaProveResult(proofValueC: proofValueC, proofValueU: proofValueU)
    }

    /// This operation allows client to verify that the output of transform() is correct,
    /// assuming that client has previously stored transformation public key.
    @objc public static func verify(transformedPassword: Data, blindedPassword: Data, tweak: Data, transformationPublicKey: Data, proofValueC: Data, proofValueU: Data) throws {
        let proxyResult = transformedPassword.withUnsafeBytes({ (transformedPasswordPointer: UnsafeRawBufferPointer) -> vscp_status_t in
            blindedPassword.withUnsafeBytes({ (blindedPasswordPointer: UnsafeRawBufferPointer) -> vscp_status_t in
                tweak.withUnsafeBytes({ (tweakPointer: UnsafeRawBufferPointer) -> vscp_status_t in
                    transformationPublicKey.withUnsafeBytes({ (transformationPublicKeyPointer: UnsafeRawBufferPointer) -> vscp_status_t in
                        proofValueC.withUnsafeBytes({ (proofValueCPointer: UnsafeRawBufferPointer) -> vscp_status_t in
                            proofValueU.withUnsafeBytes({ (proofValueUPointer: UnsafeRawBufferPointer) -> vscp_status_t in

                                return vscp_pythia_verify(vsc_data(transformedPasswordPointer.bindMemory(to: byte.self).baseAddress, transformedPassword.count), vsc_data(blindedPasswordPointer.bindMemory(to: byte.self).baseAddress, blindedPassword.count), vsc_data(tweakPointer.bindMemory(to: byte.self).baseAddress, tweak.count), vsc_data(transformationPublicKeyPointer.bindMemory(to: byte.self).baseAddress, transformationPublicKey.count), vsc_data(proofValueCPointer.bindMemory(to: byte.self).baseAddress, proofValueC.count), vsc_data(proofValueUPointer.bindMemory(to: byte.self).baseAddress, proofValueU.count))
                            })
                        })
                    })
                })
            })
        })

        try PythiaError.handleStatus(fromC: proxyResult)
    }

    /// Rotates old transformation key to new transformation key and generates 'password update token',
    /// that can update 'deblinded password'(s).
    ///
    /// This action should increment version of the 'pythia scope secret'.
    @objc public static func getPasswordUpdateToken(previousTransformationPrivateKey: Data, newTransformationPrivateKey: Data) throws -> Data {
        let passwordUpdateTokenCount = Pythia.passwordUpdateTokenBufLen()
        var passwordUpdateToken = Data(count: passwordUpdateTokenCount)
        var passwordUpdateTokenBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(passwordUpdateTokenBuf)
        }

        let proxyResult = previousTransformationPrivateKey.withUnsafeBytes({ (previousTransformationPrivateKeyPointer: UnsafeRawBufferPointer) -> vscp_status_t in
            newTransformationPrivateKey.withUnsafeBytes({ (newTransformationPrivateKeyPointer: UnsafeRawBufferPointer) -> vscp_status_t in
                passwordUpdateToken.withUnsafeMutableBytes({ (passwordUpdateTokenPointer: UnsafeMutableRawBufferPointer) -> vscp_status_t in
                    vsc_buffer_init(passwordUpdateTokenBuf)
                    vsc_buffer_use(passwordUpdateTokenBuf, passwordUpdateTokenPointer.bindMemory(to: byte.self).baseAddress, passwordUpdateTokenCount)

                    return vscp_pythia_get_password_update_token(vsc_data(previousTransformationPrivateKeyPointer.bindMemory(to: byte.self).baseAddress, previousTransformationPrivateKey.count), vsc_data(newTransformationPrivateKeyPointer.bindMemory(to: byte.self).baseAddress, newTransformationPrivateKey.count), passwordUpdateTokenBuf)
                })
            })
        })
        passwordUpdateToken.count = vsc_buffer_len(passwordUpdateTokenBuf)

        try PythiaError.handleStatus(fromC: proxyResult)

        return passwordUpdateToken
    }

    /// Updates previously stored 'deblinded password' with 'password update token'.
    /// After this call, 'transform()' called with new arguments will return corresponding values.
    @objc public static func updateDeblindedWithToken(deblindedPassword: Data, passwordUpdateToken: Data) throws -> Data {
        let updatedDeblindedPasswordCount = Pythia.deblindedPasswordBufLen()
        var updatedDeblindedPassword = Data(count: updatedDeblindedPasswordCount)
        var updatedDeblindedPasswordBuf = vsc_buffer_new()
        defer {
            vsc_buffer_delete(updatedDeblindedPasswordBuf)
        }

        let proxyResult = deblindedPassword.withUnsafeBytes({ (deblindedPasswordPointer: UnsafeRawBufferPointer) -> vscp_status_t in
            passwordUpdateToken.withUnsafeBytes({ (passwordUpdateTokenPointer: UnsafeRawBufferPointer) -> vscp_status_t in
                updatedDeblindedPassword.withUnsafeMutableBytes({ (updatedDeblindedPasswordPointer: UnsafeMutableRawBufferPointer) -> vscp_status_t in
                    vsc_buffer_init(updatedDeblindedPasswordBuf)
                    vsc_buffer_use(updatedDeblindedPasswordBuf, updatedDeblindedPasswordPointer.bindMemory(to: byte.self).baseAddress, updatedDeblindedPasswordCount)

                    return vscp_pythia_update_deblinded_with_token(vsc_data(deblindedPasswordPointer.bindMemory(to: byte.self).baseAddress, deblindedPassword.count), vsc_data(passwordUpdateTokenPointer.bindMemory(to: byte.self).baseAddress, passwordUpdateToken.count), updatedDeblindedPasswordBuf)
                })
            })
        })
        updatedDeblindedPassword.count = vsc_buffer_len(updatedDeblindedPasswordBuf)

        try PythiaError.handleStatus(fromC: proxyResult)

        return updatedDeblindedPassword
    }
}

/// Encapsulate result of method Pythia.blind()
@objc(VSCPPythiaBlindResult) public class PythiaBlindResult: NSObject {

    @objc public let blindedPassword: Data

    @objc public let blindingSecret: Data

    /// Initialize all properties.
    internal init(blindedPassword: Data, blindingSecret: Data) {
        self.blindedPassword = blindedPassword
        self.blindingSecret = blindingSecret
        super.init()
    }
}

/// Encapsulate result of method Pythia.computeTransformationKeyPair()
@objc(VSCPPythiaComputeTransformationKeyPairResult) public class PythiaComputeTransformationKeyPairResult: NSObject {

    @objc public let transformationPrivateKey: Data

    @objc public let transformationPublicKey: Data

    /// Initialize all properties.
    internal init(transformationPrivateKey: Data, transformationPublicKey: Data) {
        self.transformationPrivateKey = transformationPrivateKey
        self.transformationPublicKey = transformationPublicKey
        super.init()
    }
}

/// Encapsulate result of method Pythia.transform()
@objc(VSCPPythiaTransformResult) public class PythiaTransformResult: NSObject {

    @objc public let transformedPassword: Data

    @objc public let transformedTweak: Data

    /// Initialize all properties.
    internal init(transformedPassword: Data, transformedTweak: Data) {
        self.transformedPassword = transformedPassword
        self.transformedTweak = transformedTweak
        super.init()
    }
}

/// Encapsulate result of method Pythia.prove()
@objc(VSCPPythiaProveResult) public class PythiaProveResult: NSObject {

    @objc public let proofValueC: Data

    @objc public let proofValueU: Data

    /// Initialize all properties.
    internal init(proofValueC: Data, proofValueU: Data) {
        self.proofValueC = proofValueC
        self.proofValueU = proofValueU
        super.init()
    }
}
