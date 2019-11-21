package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"


/*
* Provide functionality for private key generation and importing that
* relies on the software default implementations.
*/
type KeyProvider struct {
    cCtx *C.vscf_key_provider_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *KeyProvider) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewKeyProvider() *KeyProvider {
    ctx := C.vscf_key_provider_new()
    obj := &KeyProvider {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKeyProviderWithCtx(ctx *C.vscf_key_provider_t /*ct2*/) *KeyProvider {
    obj := &KeyProvider {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKeyProviderCopy(ctx *C.vscf_key_provider_t /*ct2*/) *KeyProvider {
    obj := &KeyProvider {
        cCtx: C.vscf_key_provider_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *KeyProvider) Delete() {
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *KeyProvider) delete() {
    C.vscf_key_provider_delete(obj.cCtx)
}

func (obj *KeyProvider) SetRandom(random Random) {
    C.vscf_key_provider_release_random(obj.cCtx)
    C.vscf_key_provider_use_random(obj.cCtx, (*C.vscf_impl_t)(random.ctx()))
}

func (obj *KeyProvider) SetEcies(ecies Ecies) {
    C.vscf_key_provider_release_ecies(obj.cCtx)
    C.vscf_key_provider_use_ecies(obj.cCtx, (*C.vscf_ecies_t)(ecies.ctx()))
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *KeyProvider) SetupDefaults() error {
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
func (obj *KeyProvider) SetRsaParams(bitlen uint32) {
    C.vscf_key_provider_set_rsa_params(obj.cCtx, (C.size_t)(bitlen)/*pa10*/)

    return
}

/*
* Generate new private key from the given id.
*/
func (obj *KeyProvider) GeneratePrivateKey(algId AlgId) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_key_provider_generate_private_key(obj.cCtx, C.vscf_alg_id_t(algId) /*pa7*/, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return FoundationImplementationWrapPrivateKey(proxyResult) /* r4 */
}

/*
* Import private key from the PKCS#8 format.
*/
func (obj *KeyProvider) ImportPrivateKey(keyData []byte) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    keyDataData := helperWrapData (keyData)

    proxyResult := /*pr4*/C.vscf_key_provider_import_private_key(obj.cCtx, keyDataData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return FoundationImplementationWrapPrivateKey(proxyResult) /* r4 */
}

/*
* Import public key from the PKCS#8 format.
*/
func (obj *KeyProvider) ImportPublicKey(keyData []byte) (PublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    keyDataData := helperWrapData (keyData)

    proxyResult := /*pr4*/C.vscf_key_provider_import_public_key(obj.cCtx, keyDataData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return FoundationImplementationWrapPublicKey(proxyResult) /* r4 */
}

/*
* Calculate buffer size enough to hold exported public key.
*
* Precondition: public key must be exportable.
*/
func (obj *KeyProvider) ExportedPublicKeyLen(publicKey PublicKey) uint32 {
    proxyResult := /*pr4*/C.vscf_key_provider_exported_public_key_len(obj.cCtx, (*C.vscf_impl_t)(publicKey.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Export given public key to the PKCS#8 DER format.
*
* Precondition: public key must be exportable.
*/
func (obj *KeyProvider) ExportPublicKey(publicKey PublicKey) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.ExportedPublicKeyLen(publicKey.(PublicKey)) /* lg2 */))
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
func (obj *KeyProvider) ExportedPrivateKeyLen(privateKey PrivateKey) uint32 {
    proxyResult := /*pr4*/C.vscf_key_provider_exported_private_key_len(obj.cCtx, (*C.vscf_impl_t)(privateKey.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Export given private key to the PKCS#8 or SEC1 DER format.
*
* Precondition: private key must be exportable.
*/
func (obj *KeyProvider) ExportPrivateKey(privateKey PrivateKey) ([]byte, error) {
    outBuf, outBufErr := bufferNewBuffer(int(obj.ExportedPrivateKeyLen(privateKey.(PrivateKey)) /* lg2 */))
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
