//  Copyright (C) 2015-2018 Virgil Security Inc.
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

package pythia

// #cgo CFLAGS:  -I${SRCDIR}/../include
// #cgo LDFLAGS: -L${SRCDIR}/../lib -lvsc_common -lvsc_pythia -lpythia -lrelic_s -lmbedcrypto
// #include <virgil/pythia/vscp_pythia.h>
import "C"
import (
    "fmt"

    "runtime"

    "github.com/pkg/errors"
)

type Pythia struct {
    ctx *C.vscp_pythia_t
}

// Initialize pythia C module
func init() {
    C.vscp_init()
}

// New allocates underlying C context
func New() *Pythia {
    p := &Pythia{
        ctx: C.vscp_pythia_new(),
    }
    runtime.SetFinalizer(p, (*Pythia).Close)
    return p
}

// Close release underlying C context
func (p *Pythia) Close() {
    C.vscp_pythia_destroy(&p.ctx)
}

// Blind turns password into a pseudo-random string.
func (p *Pythia) Blind(password []byte) (blindedPassword, blindingSecret []byte, err error) {

    defer func() {
        if r := recover(); r != nil {
            var ok bool
            err, ok = r.(error)
            if !ok {
                err = fmt.Errorf("pkg: %v", r)
            }
        }
    }()

    C.vscp_pythia_init(p.ctx)
    defer C.vscp_pythia_cleanup(p.ctx)

    blindedPasswordBuf := NewBuf(C.vscp_pythia_blinded_password_buf_len())
    blindingSecretBuf := NewBuf(C.vscp_pythia_blinding_secret_buf_len())

    pErr := C.vscp_pythia_blind(p.ctx, WrapData(password), blindedPasswordBuf.ctx, blindingSecretBuf.ctx)
    if pErr != C.vscp_SUCCESS {
        err = errors.New("Internal Pythia error")
        return
    }

    return blindedPasswordBuf.GetData(), blindingSecretBuf.GetData(), nil
}

// Deblind unmasks value y with previously returned secret from Blind()
func (p *Pythia) Deblind(transformedPassword []byte, blindingSecret []byte) (deblindedPassword []byte, err error) {

    defer func() {
        if r := recover(); r != nil {
            var ok bool
            err, ok = r.(error)
            if !ok {
                err = fmt.Errorf("pkg: %v", r)
            }
        }
    }()

    C.vscp_pythia_init(p.ctx)
    defer C.vscp_pythia_cleanup(p.ctx)

    deblindedBuf := NewBuf(C.vscp_pythia_deblinded_password_buf_len())

    pErr := C.vscp_pythia_deblind(p.ctx, WrapData(transformedPassword), WrapData(blindingSecret), deblindedBuf.ctx)
    if pErr != C.vscp_SUCCESS {
        err = errors.New("Internal Pythia error")
        return
    }

    return deblindedBuf.GetData(), nil
}

/**
 * ComputeTransformationKeypair Computes transformation private and public key.
 *
 * @param [in] transformation_key_id - ensemble key ID used to enclose operations in subsets.
 * @param [in] pythia_secret - global common for all secret random Key.
 * @param [in] pythia_scope_secret - ensemble secret generated and versioned transparently.
 * @param [out] transformation_private_key - BN transformation_private_key Pythia's private key
 *              which was generated using pythia_secret and pythia_scope_secret.
 *              This key is used to emit proof tokens (proof_value_c, proof_value_u).
 * @param [out] transformation_public_key
 *
 * @return 0 if succeeded, -1 otherwise
 */
func (p *Pythia) ComputeTransformationKeypair(transformationKeyId, pythiaSecret, pythiaScopeSecret []byte) (privateKey, publicKey []byte, err error) {

    defer func() {
        if r := recover(); r != nil {
            var ok bool
            err, ok = r.(error)
            if !ok {
                err = fmt.Errorf("pkg: %v", r)
            }
        }
    }()

    C.vscp_pythia_init(p.ctx)
    defer C.vscp_pythia_cleanup(p.ctx)

    privateKeyBuf := NewBuf(C.vscp_pythia_transformation_private_key_buf_len())
    publicKeyBuf := NewBuf(C.vscp_pythia_transformation_public_key_buf_len())

    pErr := C.vscp_pythia_compute_transformation_key_pair(p.ctx, WrapData(transformationKeyId), WrapData(pythiaSecret), WrapData(pythiaScopeSecret), privateKeyBuf.ctx, publicKeyBuf.ctx)
    if pErr != C.vscp_SUCCESS {
        err = errors.New("Internal Pythia error")
        return
    }

    return privateKeyBuf.GetData(), publicKeyBuf.GetData(), nil
}

// Transform turns blinded password into cryptographically strong value.
/**
 * @brief Transforms blinded password using the private key, generated from pythia_secret + pythia_scope_secret.
 *
 * @param [in] blinded_password - G1 password obfuscated into a pseudo-random string.
 * @param [in] tweak - some random value used to transform a password.
 * @param [in] transformation_private_key - BN transformation private key.
 * @param [out] transformed_password - GT blinded password, protected using server secret
 *              (transformation private key + tweak).
 * @param [out] transformed_tweak - G2 tweak value turned into an elliptic curve point.
 *              This value is used by Prove() operation.
 *
 * @return 0 if succeeded, -1 otherwise
 */
func (p *Pythia) Transform(blindedPassword, tweak, transformationPrivateKey []byte) (transformedPassword, transformedTweak []byte, err error) {

    defer func() {
        if r := recover(); r != nil {
            var ok bool
            err, ok = r.(error)
            if !ok {
                err = fmt.Errorf("pkg: %v", r)
            }
        }
    }()

    C.vscp_pythia_init(p.ctx)
    defer C.vscp_pythia_cleanup(p.ctx)

    transformedPasswordBuf := NewBuf(C.vscp_pythia_transformed_password_buf_len())
    transformedTweakBuf := NewBuf(C.vscp_pythia_transformed_tweak_buf_len())

    pErr := C.vscp_pythia_transform(p.ctx, WrapData(blindedPassword), WrapData(tweak), WrapData(transformationPrivateKey), transformedPasswordBuf.ctx, transformedTweakBuf.ctx)
    if pErr != C.vscp_SUCCESS {
        err = errors.New("Internal Pythia error")
        return
    }

    return transformedPasswordBuf.GetData(), transformedTweakBuf.GetData(), nil
}

// Prove proves that server possesses secret values that are used to protect password
func (p *Pythia) Prove(transformedPassword, blindedPassword, transformedTweak, transformationPrivateKey, transformationPublicKey []byte) (proofValueC, proofValueU []byte, err error) {

    defer func() {
        if r := recover(); r != nil {
            var ok bool
            err, ok = r.(error)
            if !ok {
                err = fmt.Errorf("pkg: %v", r)
            }
        }
    }()

    C.vscp_pythia_init(p.ctx)
    defer C.vscp_pythia_cleanup(p.ctx)

    proofValueCBuf := NewBuf(C.vscp_pythia_proof_value_buf_len())
    proofValueUBuf := NewBuf(C.vscp_pythia_proof_value_buf_len())

    pErr := C.vscp_pythia_prove(p.ctx, WrapData(transformedPassword), WrapData(blindedPassword), WrapData(transformedTweak), WrapData(transformationPrivateKey), WrapData(transformationPublicKey), proofValueCBuf.ctx, proofValueUBuf.ctx)
    if pErr != C.vscp_SUCCESS {
        err = errors.New("Internal Pythia error")
        return
    }

    proofValueC = proofValueCBuf.GetData()
    proofValueU = proofValueUBuf.GetData()
    return
}

//Verify The protocol enables a client to verify that
//the output of Transform() is correct, assuming the client has
//previously stored p. The server accompanies the output
//y of the Transform() with a zero-knowledge proof (c, u) of correctness
func (p *Pythia) Verify(transformedPassword, blindedPassword, tweak, transformationPublicKey, proofValueC, proofValueU []byte) (err error) {

    defer func() {
        if r := recover(); r != nil {
            var ok bool
            err, ok = r.(error)
            if !ok {
                err = fmt.Errorf("pkg: %v", r)
            }
        }
    }()

    C.vscp_pythia_init(p.ctx)
    defer C.vscp_pythia_cleanup(p.ctx)

    pErr := C.vscp_pythia_verify(p.ctx, WrapData(transformedPassword), WrapData(blindedPassword), WrapData(tweak), WrapData(transformationPublicKey), WrapData(proofValueC), WrapData(proofValueU))

    if pErr == C.vscp_error_VERIFICATION_FAIL {
        return errors.New("Verification failed")
    }

    if pErr != C.vscp_SUCCESS {
        return errors.New("Internal Pythia error")
    }

    return nil
}

// GetPasswordUpdateToken generates token that can update protected passwords from the combination of (old) w1, msk1, ssk1 to (new) w2, msk2, ssk2
func (p *Pythia) GetPasswordUpdateToken(previousTransformationPrivateKey, newTransformationPrivateKey []byte) (passwordUpdateToken []byte, err error) {

    defer func() {
        if r := recover(); r != nil {
            var ok bool
            err, ok = r.(error)
            if !ok {
                err = fmt.Errorf("pkg: %v", r)
            }
        }
    }()

    C.vscp_pythia_init(p.ctx)
    defer C.vscp_pythia_cleanup(p.ctx)

    passwordUpdateTokenBuf := NewBuf(C.vscp_pythia_password_update_token_buf_len())

    pErr := C.vscp_pythia_get_password_update_token(p.ctx, WrapData(previousTransformationPrivateKey), WrapData(newTransformationPrivateKey), passwordUpdateTokenBuf.ctx)
    if pErr != C.vscp_SUCCESS {
        err = errors.New("Internal Pythia error")
        return
    }

    return passwordUpdateTokenBuf.GetData(), nil
}

// UpdateDeblindedWithToken updates previously stored deblinded protected password with token. After this call, Transform() called with new arguments will return corresponding values
func (p *Pythia) UpdateDeblindedWithToken(deblindedPassword, passwordUpdateToken []byte) (updatedDeblindedPassword []byte, err error) {

    defer func() {
        if r := recover(); r != nil {
            var ok bool
            err, ok = r.(error)
            if !ok {
                err = fmt.Errorf("pkg: %v", r)
            }
        }
    }()

    C.vscp_pythia_init(p.ctx)
    defer C.vscp_pythia_cleanup(p.ctx)

    updatedDeblindedPasswordBuf := NewBuf(C.vscp_pythia_deblinded_password_buf_len())

    pErr := C.vscp_pythia_update_deblinded_with_token(p.ctx, WrapData(deblindedPassword), WrapData(passwordUpdateToken), updatedDeblindedPasswordBuf.ctx)
    if pErr != C.vscp_SUCCESS {
        err = errors.New("Internal Pythia error")
        return
    }

    return updatedDeblindedPasswordBuf.GetData(), nil
}
