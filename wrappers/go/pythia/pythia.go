package pythia

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_pythia -lvsc_pythia_pb -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
// #include <virgil/crypto/pythia/vscp_pythia_public.h>
import "C"


/*
* Provide Pythia implementation based on the Virgil Security.
*/
type Pythia struct {
}

/*
* Performs global initialization of the pythia library.
* Must be called once for entire application at startup.
*/
func PythiaConfigure () error {
    proxyResult := /*pr4*/C.vscp_pythia_configure()

    err := PythiaErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Performs global cleanup of the pythia library.
* Must be called once for entire application before exit.
*/
func PythiaCleanup () {
    C.vscp_pythia_cleanup()

    return
}

/*
* Return length of the buffer needed to hold 'blinded password'.
*/
func PythiaBlindedPasswordBufLen () uint32 {
    proxyResult := /*pr4*/C.vscp_pythia_blinded_password_buf_len()

    return uint32(proxyResult) /* r9 */
}

/*
* Return length of the buffer needed to hold 'deblinded password'.
*/
func PythiaDeblindedPasswordBufLen () uint32 {
    proxyResult := /*pr4*/C.vscp_pythia_deblinded_password_buf_len()

    return uint32(proxyResult) /* r9 */
}

/*
* Return length of the buffer needed to hold 'blinding secret'.
*/
func PythiaBlindingSecretBufLen () uint32 {
    proxyResult := /*pr4*/C.vscp_pythia_blinding_secret_buf_len()

    return uint32(proxyResult) /* r9 */
}

/*
* Return length of the buffer needed to hold 'transformation private key'.
*/
func PythiaTransformationPrivateKeyBufLen () uint32 {
    proxyResult := /*pr4*/C.vscp_pythia_transformation_private_key_buf_len()

    return uint32(proxyResult) /* r9 */
}

/*
* Return length of the buffer needed to hold 'transformation public key'.
*/
func PythiaTransformationPublicKeyBufLen () uint32 {
    proxyResult := /*pr4*/C.vscp_pythia_transformation_public_key_buf_len()

    return uint32(proxyResult) /* r9 */
}

/*
* Return length of the buffer needed to hold 'transformed password'.
*/
func PythiaTransformedPasswordBufLen () uint32 {
    proxyResult := /*pr4*/C.vscp_pythia_transformed_password_buf_len()

    return uint32(proxyResult) /* r9 */
}

/*
* Return length of the buffer needed to hold 'transformed tweak'.
*/
func PythiaTransformedTweakBufLen () uint32 {
    proxyResult := /*pr4*/C.vscp_pythia_transformed_tweak_buf_len()

    return uint32(proxyResult) /* r9 */
}

/*
* Return length of the buffer needed to hold 'proof value'.
*/
func PythiaProofValueBufLen () uint32 {
    proxyResult := /*pr4*/C.vscp_pythia_proof_value_buf_len()

    return uint32(proxyResult) /* r9 */
}

/*
* Return length of the buffer needed to hold 'password update token'.
*/
func PythiaPasswordUpdateTokenBufLen () uint32 {
    proxyResult := /*pr4*/C.vscp_pythia_password_update_token_buf_len()

    return uint32(proxyResult) /* r9 */
}

/*
* Blinds password. Turns password into a pseudo-random string.
* This step is necessary to prevent 3rd-parties from knowledge of end user's password.
*/
func PythiaBlind (password []byte) ([]byte, []byte, error) {
    blindedPasswordBuf, blindedPasswordBufErr := bufferNewBuffer(int(PythiaBlindedPasswordBufLen() /* lg1 */))
    if blindedPasswordBufErr != nil {
        return nil, nil, blindedPasswordBufErr
    }
    defer blindedPasswordBuf.Delete()

    blindingSecretBuf, blindingSecretBufErr := bufferNewBuffer(int(PythiaBlindingSecretBufLen() /* lg1 */))
    if blindingSecretBufErr != nil {
        return nil, nil, blindingSecretBufErr
    }
    defer blindingSecretBuf.Delete()
    passwordData := helperWrapData (password)

    proxyResult := /*pr4*/C.vscp_pythia_blind(passwordData, blindedPasswordBuf.ctx, blindingSecretBuf.ctx)

    err := PythiaErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, nil, err
    }

    return blindedPasswordBuf.getData() /* r7 */, blindingSecretBuf.getData() /* r7 */, nil
}

/*
* Deblinds 'transformed password' value with previously returned 'blinding secret' from blind().
*/
func PythiaDeblind (transformedPassword []byte, blindingSecret []byte) ([]byte, error) {
    deblindedPasswordBuf, deblindedPasswordBufErr := bufferNewBuffer(int(PythiaDeblindedPasswordBufLen() /* lg1 */))
    if deblindedPasswordBufErr != nil {
        return nil, deblindedPasswordBufErr
    }
    defer deblindedPasswordBuf.Delete()
    transformedPasswordData := helperWrapData (transformedPassword)
    blindingSecretData := helperWrapData (blindingSecret)

    proxyResult := /*pr4*/C.vscp_pythia_deblind(transformedPasswordData, blindingSecretData, deblindedPasswordBuf.ctx)

    err := PythiaErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return deblindedPasswordBuf.getData() /* r7 */, nil
}

/*
* Computes transformation private and public key.
*/
func PythiaComputeTransformationKeyPair (transformationKeyId []byte, pythiaSecret []byte, pythiaScopeSecret []byte) ([]byte, []byte, error) {
    transformationPrivateKeyBuf, transformationPrivateKeyBufErr := bufferNewBuffer(int(PythiaTransformationPrivateKeyBufLen() /* lg1 */))
    if transformationPrivateKeyBufErr != nil {
        return nil, nil, transformationPrivateKeyBufErr
    }
    defer transformationPrivateKeyBuf.Delete()

    transformationPublicKeyBuf, transformationPublicKeyBufErr := bufferNewBuffer(int(PythiaTransformationPublicKeyBufLen() /* lg1 */))
    if transformationPublicKeyBufErr != nil {
        return nil, nil, transformationPublicKeyBufErr
    }
    defer transformationPublicKeyBuf.Delete()
    transformationKeyIdData := helperWrapData (transformationKeyId)
    pythiaSecretData := helperWrapData (pythiaSecret)
    pythiaScopeSecretData := helperWrapData (pythiaScopeSecret)

    proxyResult := /*pr4*/C.vscp_pythia_compute_transformation_key_pair(transformationKeyIdData, pythiaSecretData, pythiaScopeSecretData, transformationPrivateKeyBuf.ctx, transformationPublicKeyBuf.ctx)

    err := PythiaErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, nil, err
    }

    return transformationPrivateKeyBuf.getData() /* r7 */, transformationPublicKeyBuf.getData() /* r7 */, nil
}

/*
* Transforms blinded password using transformation private key.
*/
func PythiaTransform (blindedPassword []byte, tweak []byte, transformationPrivateKey []byte) ([]byte, []byte, error) {
    transformedPasswordBuf, transformedPasswordBufErr := bufferNewBuffer(int(PythiaTransformedPasswordBufLen() /* lg1 */))
    if transformedPasswordBufErr != nil {
        return nil, nil, transformedPasswordBufErr
    }
    defer transformedPasswordBuf.Delete()

    transformedTweakBuf, transformedTweakBufErr := bufferNewBuffer(int(PythiaTransformedTweakBufLen() /* lg1 */))
    if transformedTweakBufErr != nil {
        return nil, nil, transformedTweakBufErr
    }
    defer transformedTweakBuf.Delete()
    blindedPasswordData := helperWrapData (blindedPassword)
    tweakData := helperWrapData (tweak)
    transformationPrivateKeyData := helperWrapData (transformationPrivateKey)

    proxyResult := /*pr4*/C.vscp_pythia_transform(blindedPasswordData, tweakData, transformationPrivateKeyData, transformedPasswordBuf.ctx, transformedTweakBuf.ctx)

    err := PythiaErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, nil, err
    }

    return transformedPasswordBuf.getData() /* r7 */, transformedTweakBuf.getData() /* r7 */, nil
}

/*
* Generates proof that server possesses secret values that were used to transform password.
*/
func PythiaProve (transformedPassword []byte, blindedPassword []byte, transformedTweak []byte, transformationPrivateKey []byte, transformationPublicKey []byte) ([]byte, []byte, error) {
    proofValueCBuf, proofValueCBufErr := bufferNewBuffer(int(PythiaProofValueBufLen() /* lg1 */))
    if proofValueCBufErr != nil {
        return nil, nil, proofValueCBufErr
    }
    defer proofValueCBuf.Delete()

    proofValueUBuf, proofValueUBufErr := bufferNewBuffer(int(PythiaProofValueBufLen() /* lg1 */))
    if proofValueUBufErr != nil {
        return nil, nil, proofValueUBufErr
    }
    defer proofValueUBuf.Delete()
    transformedPasswordData := helperWrapData (transformedPassword)
    blindedPasswordData := helperWrapData (blindedPassword)
    transformedTweakData := helperWrapData (transformedTweak)
    transformationPrivateKeyData := helperWrapData (transformationPrivateKey)
    transformationPublicKeyData := helperWrapData (transformationPublicKey)

    proxyResult := /*pr4*/C.vscp_pythia_prove(transformedPasswordData, blindedPasswordData, transformedTweakData, transformationPrivateKeyData, transformationPublicKeyData, proofValueCBuf.ctx, proofValueUBuf.ctx)

    err := PythiaErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, nil, err
    }

    return proofValueCBuf.getData() /* r7 */, proofValueUBuf.getData() /* r7 */, nil
}

/*
* This operation allows client to verify that the output of transform() is correct,
* assuming that client has previously stored transformation public key.
*/
func PythiaVerify (transformedPassword []byte, blindedPassword []byte, tweak []byte, transformationPublicKey []byte, proofValueC []byte, proofValueU []byte) (bool, error) {
    var error C.vscp_error_t
    C.vscp_error_reset(&error)
    transformedPasswordData := helperWrapData (transformedPassword)
    blindedPasswordData := helperWrapData (blindedPassword)
    tweakData := helperWrapData (tweak)
    transformationPublicKeyData := helperWrapData (transformationPublicKey)
    proofValueCData := helperWrapData (proofValueC)
    proofValueUData := helperWrapData (proofValueU)

    proxyResult := /*pr4*/C.vscp_pythia_verify(transformedPasswordData, blindedPasswordData, tweakData, transformationPublicKeyData, proofValueCData, proofValueUData, &error)

    err := PythiaErrorHandleStatus(error.status)
    if err != nil {
        return false, err
    }

    return bool(proxyResult) /* r9 */, nil
}

/*
* Rotates old transformation key to new transformation key and generates 'password update token',
* that can update 'deblinded password'(s).
*
* This action should increment version of the 'pythia scope secret'.
*/
func PythiaGetPasswordUpdateToken (previousTransformationPrivateKey []byte, newTransformationPrivateKey []byte) ([]byte, error) {
    passwordUpdateTokenBuf, passwordUpdateTokenBufErr := bufferNewBuffer(int(PythiaPasswordUpdateTokenBufLen() /* lg1 */))
    if passwordUpdateTokenBufErr != nil {
        return nil, passwordUpdateTokenBufErr
    }
    defer passwordUpdateTokenBuf.Delete()
    previousTransformationPrivateKeyData := helperWrapData (previousTransformationPrivateKey)
    newTransformationPrivateKeyData := helperWrapData (newTransformationPrivateKey)

    proxyResult := /*pr4*/C.vscp_pythia_get_password_update_token(previousTransformationPrivateKeyData, newTransformationPrivateKeyData, passwordUpdateTokenBuf.ctx)

    err := PythiaErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return passwordUpdateTokenBuf.getData() /* r7 */, nil
}

/*
* Updates previously stored 'deblinded password' with 'password update token'.
* After this call, 'transform()' called with new arguments will return corresponding values.
*/
func PythiaUpdateDeblindedWithToken (deblindedPassword []byte, passwordUpdateToken []byte) ([]byte, error) {
    updatedDeblindedPasswordBuf, updatedDeblindedPasswordBufErr := bufferNewBuffer(int(PythiaDeblindedPasswordBufLen() /* lg1 */))
    if updatedDeblindedPasswordBufErr != nil {
        return nil, updatedDeblindedPasswordBufErr
    }
    defer updatedDeblindedPasswordBuf.Delete()
    deblindedPasswordData := helperWrapData (deblindedPassword)
    passwordUpdateTokenData := helperWrapData (passwordUpdateToken)

    proxyResult := /*pr4*/C.vscp_pythia_update_deblinded_with_token(deblindedPasswordData, passwordUpdateTokenData, updatedDeblindedPasswordBuf.ctx)

    err := PythiaErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return updatedDeblindedPasswordBuf.getData() /* r7 */, nil
}
