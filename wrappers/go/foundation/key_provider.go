package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Provide functionality for private key generation and importing that
* relies on the software default implementations.
*/
type KeyProvider struct {
    cCtx *C.vscf_key_provider_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *KeyProvider) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewKeyProvider () *KeyProvider {
    ctx := C.vscf_key_provider_new()
    return &KeyProvider {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKeyProviderWithCtx (ctx *C.vscf_key_provider_t /*ct2*/) *KeyProvider {
    return &KeyProvider {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKeyProviderCopy (ctx *C.vscf_key_provider_t /*ct2*/) *KeyProvider {
    return &KeyProvider {
        cCtx: C.vscf_key_provider_shallow_copy(ctx),
    }
}

/*
* Release underlying C context.
*/
func (obj *KeyProvider) Delete () {
    C.vscf_key_provider_delete(obj.cCtx)
}

func (obj *KeyProvider) SetRandom (random IRandom) {
    C.vscf_key_provider_release_random(obj.cCtx)
    C.vscf_key_provider_use_random(obj.cCtx, (*C.vscf_impl_t)(random.ctx()))
}

func (obj *KeyProvider) SetEcies (ecies Ecies) {
    C.vscf_key_provider_release_ecies(obj.cCtx)
    C.vscf_key_provider_use_ecies(obj.cCtx, (*C.vscf_ecies_t)(ecies.ctx()))
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *KeyProvider) SetupDefaults () error {
    proxyResult := /*pr4*/C.vscf_key_provider_setup_defaults(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Setup parameters that is used during RSA key generation.
*/
func (obj *KeyProvider) SetRsaParams (bitlen uint32) {
    C.vscf_key_provider_set_rsa_params(obj.cCtx, (C.size_t)(bitlen)/*pa10*/)

    return
}

/*
* Generate new private key from the given id.
*/
func (obj *KeyProvider) GeneratePrivateKey (algId AlgId) (IPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_key_provider_generate_private_key(obj.cCtx, C.vscf_alg_id_t(algId) /*pa7*/, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return FoundationImplementationWrapIPrivateKey(proxyResult) /* r4 */
}

/*
* Import private key from the PKCS#8 format.
*/
func (obj *KeyProvider) ImportPrivateKey (keyData []byte) (IPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    keyDataData := helperWrapData (keyData)

    proxyResult := /*pr4*/C.vscf_key_provider_import_private_key(obj.cCtx, keyDataData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return FoundationImplementationWrapIPrivateKey(proxyResult) /* r4 */
}

/*
* Import public key from the PKCS#8 format.
*/
func (obj *KeyProvider) ImportPublicKey (keyData []byte) (IPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    keyDataData := helperWrapData (keyData)

    proxyResult := /*pr4*/C.vscf_key_provider_import_public_key(obj.cCtx, keyDataData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return FoundationImplementationWrapIPublicKey(proxyResult) /* r4 */
}

/*
* Calculate buffer size enough to hold exported public key.
*
* Precondition: public key must be exportable.
*/
func (obj *KeyProvider) ExportedPublicKeyLen (publicKey IPublicKey) uint32 {
    proxyResult := /*pr4*/C.vscf_key_provider_exported_public_key_len(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Export given public key to the PKCS#8 DER format.
*
* Precondition: public key must be exportable.
*/
func (obj *KeyProvider) ExportPublicKey (publicKey IPublicKey) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.ExportedPublicKeyLen(publicKey.(IPublicKey)) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()


    proxyResult := /*pr4*/C.vscf_key_provider_export_public_key(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outBuf.getData() /* r7 */, nil
}

/*
* Calculate buffer size enough to hold exported private key.
*
* Precondition: private key must be exportable.
*/
func (obj *KeyProvider) ExportedPrivateKeyLen (privateKey IPrivateKey) uint32 {
    proxyResult := /*pr4*/C.vscf_key_provider_exported_private_key_len(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Export given private key to the PKCS#8 or SEC1 DER format.
*
* Precondition: private key must be exportable.
*/
func (obj *KeyProvider) ExportPrivateKey (privateKey IPrivateKey) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.ExportedPrivateKeyLen(privateKey.(IPrivateKey)) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.Delete()


    proxyResult := /*pr4*/C.vscf_key_provider_export_private_key(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outBuf.getData() /* r7 */, nil
}
