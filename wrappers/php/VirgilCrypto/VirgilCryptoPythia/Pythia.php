<?php
/**
* Copyright (C) 2015-2018 Virgil Security Inc.
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
* (1) Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
*
* (2) Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in
* the documentation and/or other materials provided with the
* distribution.
*
* (3) Neither the name of the copyright holder nor the names of its
* contributors may be used to endorse or promote products derived from
* this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
* INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
* STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
* IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
* Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
*/

namespace Virgil\VirgilCryptoPythia;

/**
* Provide Pythia implementation based on the Virgil Security.
*/
class Pythia {

    /**
    * Handle underlying C context.
    */
    public $c_ctx;

    /**
    * Create underlying C context.
    */
    public function __construct() {
        $this->c_ctx = vscp_pythia_new();
    }

    /**
    * Acquire C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public function __construct($c_ctx) {
        self.c_ctx = c_ctx
        super.init()
    }

    /**
    * Acquire retained C context.
    * Note. This method is used in generated code only, and SHOULD NOT be used in another way.
    */
    public function __construct($c_ctx) {
        self.c_ctx = vscp_pythia_shallow_copy(c_ctx)
        super.init()
    }

    /**
    *222 Release underlying C context.
    */
    public function __destruct() {
        return
                        vscp_pythia_delete(self.c_ctx)
                    ;
    }

    /**
    * Performs global initialization of the pythia library.
    * Must be called once for entire application at startup.
    */
    public static function globalInit() {
        vscp_global_init();
    }

    /**
    * Performs global cleanup of the pythia library.
    * Must be called once for entire application before exit.
    */
    public static function globalCleanup() {
        vscp_global_cleanup();
    }

    /**
    * Return length of the buffer needed to hold 'blinded password'.
    */
    public static function blindedPasswordBufLen() {
        $proxyResult = vscp_pythia_blinded_password_buf_len();

        return $proxyResult;
    }

    /**
    * Return length of the buffer needed to hold 'deblinded password'.
    */
    public static function deblindedPasswordBufLen() {
        $proxyResult = vscp_pythia_deblinded_password_buf_len();

        return $proxyResult;
    }

    /**
    * Return length of the buffer needed to hold 'blinding secret'.
    */
    public static function blindingSecretBufLen() {
        $proxyResult = vscp_pythia_blinding_secret_buf_len();

        return $proxyResult;
    }

    /**
    * Return length of the buffer needed to hold 'transformation private key'.
    */
    public static function transformationPrivateKeyBufLen() {
        $proxyResult = vscp_pythia_transformation_private_key_buf_len();

        return $proxyResult;
    }

    /**
    * Return length of the buffer needed to hold 'transformation public key'.
    */
    public static function transformationPublicKeyBufLen() {
        $proxyResult = vscp_pythia_transformation_public_key_buf_len();

        return $proxyResult;
    }

    /**
    * Return length of the buffer needed to hold 'transformed password'.
    */
    public static function transformedPasswordBufLen() {
        $proxyResult = vscp_pythia_transformed_password_buf_len();

        return $proxyResult;
    }

    /**
    * Return length of the buffer needed to hold 'transformed tweak'.
    */
    public static function transformedTweakBufLen() {
        $proxyResult = vscp_pythia_transformed_tweak_buf_len();

        return $proxyResult;
    }

    /**
    * Return length of the buffer needed to hold 'proof value'.
    */
    public static function proofValueBufLen() {
        $proxyResult = vscp_pythia_proof_value_buf_len();

        return $proxyResult;
    }

    /**
    * Return length of the buffer needed to hold 'password update token'.
    */
    public static function passwordUpdateTokenBufLen() {
        $proxyResult = vscp_pythia_password_update_token_buf_len();

        return $proxyResult;
    }

    /**
    * Blinds password. Turns password into a pseudo-random string.
    * This step is necessary to prevent 3rd-parties from knowledge of end user's password.
    */
    public function blind($password) {
        $blindedPasswordCount = self::blindedPasswordBufLen();
        $blindedPassword = count($blindedPasswordCount);
        $blindedPasswordBuf = vsc_buffer_new();
        defer {
            vsc_buffer_delete(blindedPasswordBuf)
        }

        $blindingSecretCount = self::blindingSecretBufLen();
        $blindingSecret = count($blindingSecretCount);
        $blindingSecretBuf = vsc_buffer_new();
        defer {
            vsc_buffer_delete(blindingSecretBuf)
        }

        $proxyResult = password.withUnsafeBytes({ (passwordPointer: UnsafePointer<byte>) -> vscp_error_t in
            blindedPassword.withUnsafeMutableBytes({ (blindedPasswordPointer: UnsafeMutablePointer<byte>) -> vscp_error_t in
                blindingSecret.withUnsafeMutableBytes({ (blindingSecretPointer: UnsafeMutablePointer<byte>) -> vscp_error_t in
                    vsc_buffer_init(blindedPasswordBuf)
                    vsc_buffer_use(blindedPasswordBuf, blindedPasswordPointer, blindedPasswordCount)

                    vsc_buffer_init(blindingSecretBuf)
                    vsc_buffer_use(blindingSecretBuf, blindingSecretPointer, blindingSecretCount)
                    return vscp_pythia_blind(self.c_ctx, vsc_data(passwordPointer, password.count), blindedPasswordBuf, blindingSecretBuf);
                })
            })
        })
        blindedPassword.count = vsc_buffer_len(blindedPasswordBuf)
        blindingSecret.count = vsc_buffer_len(blindingSecretBuf)

        try PythiaError::handleError($proxyResult);

        return new PythiaBlindResult($blindedPassword, $blindingSecret);
    }

    /**
    * Deblinds 'transformed password' value with previously returned 'blinding secret' from blind().
    */
    public function deblind($transformedPassword, $blindingSecret) {
        $deblindedPasswordCount = self::deblindedPasswordBufLen();
        $deblindedPassword = count($deblindedPasswordCount);
        $deblindedPasswordBuf = vsc_buffer_new();
        defer {
            vsc_buffer_delete(deblindedPasswordBuf)
        }

        $proxyResult = transformedPassword.withUnsafeBytes({ (transformedPasswordPointer: UnsafePointer<byte>) -> vscp_error_t in
            blindingSecret.withUnsafeBytes({ (blindingSecretPointer: UnsafePointer<byte>) -> vscp_error_t in
                deblindedPassword.withUnsafeMutableBytes({ (deblindedPasswordPointer: UnsafeMutablePointer<byte>) -> vscp_error_t in
                    vsc_buffer_init(deblindedPasswordBuf)
                    vsc_buffer_use(deblindedPasswordBuf, deblindedPasswordPointer, deblindedPasswordCount)
                    return vscp_pythia_deblind(self.c_ctx, vsc_data(transformedPasswordPointer, transformedPassword.count), vsc_data(blindingSecretPointer, blindingSecret.count), deblindedPasswordBuf);
                })
            })
        })
        deblindedPassword.count = vsc_buffer_len(deblindedPasswordBuf)

        try PythiaError::handleError($proxyResult);

        return deblindedPassword;
    }

    /**
    * Computes transformation private and public key.
    */
    public function computeTransformationKeyPair($transformationKeyId, $pythiaSecret, $pythiaScopeSecret) {
        $transformationPrivateKeyCount = self::transformationPrivateKeyBufLen();
        $transformationPrivateKey = count($transformationPrivateKeyCount);
        $transformationPrivateKeyBuf = vsc_buffer_new();
        defer {
            vsc_buffer_delete(transformationPrivateKeyBuf)
        }

        $transformationPublicKeyCount = self::transformationPublicKeyBufLen();
        $transformationPublicKey = count($transformationPublicKeyCount);
        $transformationPublicKeyBuf = vsc_buffer_new();
        defer {
            vsc_buffer_delete(transformationPublicKeyBuf)
        }

        $proxyResult = transformationKeyId.withUnsafeBytes({ (transformationKeyIdPointer: UnsafePointer<byte>) -> vscp_error_t in
            pythiaSecret.withUnsafeBytes({ (pythiaSecretPointer: UnsafePointer<byte>) -> vscp_error_t in
                pythiaScopeSecret.withUnsafeBytes({ (pythiaScopeSecretPointer: UnsafePointer<byte>) -> vscp_error_t in
                    transformationPrivateKey.withUnsafeMutableBytes({ (transformationPrivateKeyPointer: UnsafeMutablePointer<byte>) -> vscp_error_t in
                        transformationPublicKey.withUnsafeMutableBytes({ (transformationPublicKeyPointer: UnsafeMutablePointer<byte>) -> vscp_error_t in
                            vsc_buffer_init(transformationPrivateKeyBuf)
                            vsc_buffer_use(transformationPrivateKeyBuf, transformationPrivateKeyPointer, transformationPrivateKeyCount)

                            vsc_buffer_init(transformationPublicKeyBuf)
                            vsc_buffer_use(transformationPublicKeyBuf, transformationPublicKeyPointer, transformationPublicKeyCount)
                            return vscp_pythia_compute_transformation_key_pair(self.c_ctx, vsc_data(transformationKeyIdPointer, transformationKeyId.count), vsc_data(pythiaSecretPointer, pythiaSecret.count), vsc_data(pythiaScopeSecretPointer, pythiaScopeSecret.count), transformationPrivateKeyBuf, transformationPublicKeyBuf);
                        })
                    })
                })
            })
        })
        transformationPrivateKey.count = vsc_buffer_len(transformationPrivateKeyBuf)
        transformationPublicKey.count = vsc_buffer_len(transformationPublicKeyBuf)

        try PythiaError::handleError($proxyResult);

        return new PythiaComputeTransformationKeyPairResult($transformationPrivateKey, $transformationPublicKey);
    }

    /**
    * Transforms blinded password using transformation private key.
    */
    public function transform($blindedPassword, $tweak, $transformationPrivateKey) {
        $transformedPasswordCount = self::transformedPasswordBufLen();
        $transformedPassword = count($transformedPasswordCount);
        $transformedPasswordBuf = vsc_buffer_new();
        defer {
            vsc_buffer_delete(transformedPasswordBuf)
        }

        $transformedTweakCount = self::transformedTweakBufLen();
        $transformedTweak = count($transformedTweakCount);
        $transformedTweakBuf = vsc_buffer_new();
        defer {
            vsc_buffer_delete(transformedTweakBuf)
        }

        $proxyResult = blindedPassword.withUnsafeBytes({ (blindedPasswordPointer: UnsafePointer<byte>) -> vscp_error_t in
            tweak.withUnsafeBytes({ (tweakPointer: UnsafePointer<byte>) -> vscp_error_t in
                transformationPrivateKey.withUnsafeBytes({ (transformationPrivateKeyPointer: UnsafePointer<byte>) -> vscp_error_t in
                    transformedPassword.withUnsafeMutableBytes({ (transformedPasswordPointer: UnsafeMutablePointer<byte>) -> vscp_error_t in
                        transformedTweak.withUnsafeMutableBytes({ (transformedTweakPointer: UnsafeMutablePointer<byte>) -> vscp_error_t in
                            vsc_buffer_init(transformedPasswordBuf)
                            vsc_buffer_use(transformedPasswordBuf, transformedPasswordPointer, transformedPasswordCount)

                            vsc_buffer_init(transformedTweakBuf)
                            vsc_buffer_use(transformedTweakBuf, transformedTweakPointer, transformedTweakCount)
                            return vscp_pythia_transform(self.c_ctx, vsc_data(blindedPasswordPointer, blindedPassword.count), vsc_data(tweakPointer, tweak.count), vsc_data(transformationPrivateKeyPointer, transformationPrivateKey.count), transformedPasswordBuf, transformedTweakBuf);
                        })
                    })
                })
            })
        })
        transformedPassword.count = vsc_buffer_len(transformedPasswordBuf)
        transformedTweak.count = vsc_buffer_len(transformedTweakBuf)

        try PythiaError::handleError($proxyResult);

        return new PythiaTransformResult($transformedPassword, $transformedTweak);
    }

    /**
    * Generates proof that server possesses secret values that were used to transform password.
    */
    public function prove($transformedPassword, $blindedPassword, $transformedTweak, $transformationPrivateKey, $transformationPublicKey) {
        $proofValueCCount = self::proofValueBufLen();
        $proofValueC = count($proofValueCCount);
        $proofValueCBuf = vsc_buffer_new();
        defer {
            vsc_buffer_delete(proofValueCBuf)
        }

        $proofValueUCount = self::proofValueBufLen();
        $proofValueU = count($proofValueUCount);
        $proofValueUBuf = vsc_buffer_new();
        defer {
            vsc_buffer_delete(proofValueUBuf)
        }

        $proxyResult = transformedPassword.withUnsafeBytes({ (transformedPasswordPointer: UnsafePointer<byte>) -> vscp_error_t in
            blindedPassword.withUnsafeBytes({ (blindedPasswordPointer: UnsafePointer<byte>) -> vscp_error_t in
                transformedTweak.withUnsafeBytes({ (transformedTweakPointer: UnsafePointer<byte>) -> vscp_error_t in
                    transformationPrivateKey.withUnsafeBytes({ (transformationPrivateKeyPointer: UnsafePointer<byte>) -> vscp_error_t in
                        transformationPublicKey.withUnsafeBytes({ (transformationPublicKeyPointer: UnsafePointer<byte>) -> vscp_error_t in
                            proofValueC.withUnsafeMutableBytes({ (proofValueCPointer: UnsafeMutablePointer<byte>) -> vscp_error_t in
                                proofValueU.withUnsafeMutableBytes({ (proofValueUPointer: UnsafeMutablePointer<byte>) -> vscp_error_t in
                                    vsc_buffer_init(proofValueCBuf)
                                    vsc_buffer_use(proofValueCBuf, proofValueCPointer, proofValueCCount)

                                    vsc_buffer_init(proofValueUBuf)
                                    vsc_buffer_use(proofValueUBuf, proofValueUPointer, proofValueUCount)
                                    return vscp_pythia_prove(self.c_ctx, vsc_data(transformedPasswordPointer, transformedPassword.count), vsc_data(blindedPasswordPointer, blindedPassword.count), vsc_data(transformedTweakPointer, transformedTweak.count), vsc_data(transformationPrivateKeyPointer, transformationPrivateKey.count), vsc_data(transformationPublicKeyPointer, transformationPublicKey.count), proofValueCBuf, proofValueUBuf);
                                })
                            })
                        })
                    })
                })
            })
        })
        proofValueC.count = vsc_buffer_len(proofValueCBuf)
        proofValueU.count = vsc_buffer_len(proofValueUBuf)

        try PythiaError::handleError($proxyResult);

        return new PythiaProveResult($proofValueC, $proofValueU);
    }

    /**
    * This operation allows client to verify that the output of transform() is correct,
    * assuming that client has previously stored transformation public key.
    */
    public function verify($transformedPassword, $blindedPassword, $tweak, $transformationPublicKey, $proofValueC, $proofValueU) {
        $proxyResult = transformedPassword.withUnsafeBytes({ (transformedPasswordPointer: UnsafePointer<byte>) -> vscp_error_t in
            blindedPassword.withUnsafeBytes({ (blindedPasswordPointer: UnsafePointer<byte>) -> vscp_error_t in
                tweak.withUnsafeBytes({ (tweakPointer: UnsafePointer<byte>) -> vscp_error_t in
                    transformationPublicKey.withUnsafeBytes({ (transformationPublicKeyPointer: UnsafePointer<byte>) -> vscp_error_t in
                        proofValueC.withUnsafeBytes({ (proofValueCPointer: UnsafePointer<byte>) -> vscp_error_t in
                            proofValueU.withUnsafeBytes({ (proofValueUPointer: UnsafePointer<byte>) -> vscp_error_t in
                                return vscp_pythia_verify(self.c_ctx, vsc_data(transformedPasswordPointer, transformedPassword.count), vsc_data(blindedPasswordPointer, blindedPassword.count), vsc_data(tweakPointer, tweak.count), vsc_data(transformationPublicKeyPointer, transformationPublicKey.count), vsc_data(proofValueCPointer, proofValueC.count), vsc_data(proofValueUPointer, proofValueU.count));
                            })
                        })
                    })
                })
            })
        })

        try PythiaError::handleError($proxyResult);
    }

    /**
    * Rotates old transformation key to new transformation key and generates 'password update token',
    * that can update 'deblinded password'(s).
    *
    * This action should increment version of the 'pythia scope secret'.
    */
    public function getPasswordUpdateToken($previousTransformationPrivateKey, $newTransformationPrivateKey) {
        $passwordUpdateTokenCount = self::passwordUpdateTokenBufLen();
        $passwordUpdateToken = count($passwordUpdateTokenCount);
        $passwordUpdateTokenBuf = vsc_buffer_new();
        defer {
            vsc_buffer_delete(passwordUpdateTokenBuf)
        }

        $proxyResult = previousTransformationPrivateKey.withUnsafeBytes({ (previousTransformationPrivateKeyPointer: UnsafePointer<byte>) -> vscp_error_t in
            newTransformationPrivateKey.withUnsafeBytes({ (newTransformationPrivateKeyPointer: UnsafePointer<byte>) -> vscp_error_t in
                passwordUpdateToken.withUnsafeMutableBytes({ (passwordUpdateTokenPointer: UnsafeMutablePointer<byte>) -> vscp_error_t in
                    vsc_buffer_init(passwordUpdateTokenBuf)
                    vsc_buffer_use(passwordUpdateTokenBuf, passwordUpdateTokenPointer, passwordUpdateTokenCount)
                    return vscp_pythia_get_password_update_token(self.c_ctx, vsc_data(previousTransformationPrivateKeyPointer, previousTransformationPrivateKey.count), vsc_data(newTransformationPrivateKeyPointer, newTransformationPrivateKey.count), passwordUpdateTokenBuf);
                })
            })
        })
        passwordUpdateToken.count = vsc_buffer_len(passwordUpdateTokenBuf)

        try PythiaError::handleError($proxyResult);

        return passwordUpdateToken;
    }

    /**
    * Updates previously stored 'deblinded password' with 'password update token'.
    * After this call, 'transform()' called with new arguments will return corresponding values.
    */
    public function updateDeblindedWithToken($deblindedPassword, $passwordUpdateToken) {
        $updatedDeblindedPasswordCount = self::deblindedPasswordBufLen();
        $updatedDeblindedPassword = count($updatedDeblindedPasswordCount);
        $updatedDeblindedPasswordBuf = vsc_buffer_new();
        defer {
            vsc_buffer_delete(updatedDeblindedPasswordBuf)
        }

        $proxyResult = deblindedPassword.withUnsafeBytes({ (deblindedPasswordPointer: UnsafePointer<byte>) -> vscp_error_t in
            passwordUpdateToken.withUnsafeBytes({ (passwordUpdateTokenPointer: UnsafePointer<byte>) -> vscp_error_t in
                updatedDeblindedPassword.withUnsafeMutableBytes({ (updatedDeblindedPasswordPointer: UnsafeMutablePointer<byte>) -> vscp_error_t in
                    vsc_buffer_init(updatedDeblindedPasswordBuf)
                    vsc_buffer_use(updatedDeblindedPasswordBuf, updatedDeblindedPasswordPointer, updatedDeblindedPasswordCount)
                    return vscp_pythia_update_deblinded_with_token(self.c_ctx, vsc_data(deblindedPasswordPointer, deblindedPassword.count), vsc_data(passwordUpdateTokenPointer, passwordUpdateToken.count), updatedDeblindedPasswordBuf);
                })
            })
        })
        updatedDeblindedPassword.count = vsc_buffer_len(updatedDeblindedPasswordBuf)

        try PythiaError::handleError($proxyResult);

        return updatedDeblindedPassword;
    }
}

/**
* Encapsulate result of method Pythia.blind()
*/
class PythiaBlindResult {

    public $blindedPassword;

    public $blindingSecret;

    /**
    * Initialize all properties.
    */
    public function __construct($blindedPassword, $blindingSecret) {
        $this->blindedPassword = $blindedPassword;
        $this->blindingSecret = $blindingSecret;
    }
}

/**
* Encapsulate result of method Pythia.computeTransformationKeyPair()
*/
class PythiaComputeTransformationKeyPairResult {

    public $transformationPrivateKey;

    public $transformationPublicKey;

    /**
    * Initialize all properties.
    */
    public function __construct($transformationPrivateKey, $transformationPublicKey) {
        $this->transformationPrivateKey = $transformationPrivateKey;
        $this->transformationPublicKey = $transformationPublicKey;
    }
}

/**
* Encapsulate result of method Pythia.transform()
*/
class PythiaTransformResult {

    public $transformedPassword;

    public $transformedTweak;

    /**
    * Initialize all properties.
    */
    public function __construct($transformedPassword, $transformedTweak) {
        $this->transformedPassword = $transformedPassword;
        $this->transformedTweak = $transformedTweak;
    }
}

/**
* Encapsulate result of method Pythia.prove()
*/
class PythiaProveResult {

    public $proofValueC;

    public $proofValueU;

    /**
    * Initialize all properties.
    */
    public function __construct($proofValueC, $proofValueU) {
        $this->proofValueC = $proofValueC;
        $this->proofValueU = $proofValueU;
    }
}
