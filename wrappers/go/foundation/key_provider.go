package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Provide functionality for private key generation and importing that
* relies on the software default implementations.
*/
type KeyProvider struct {
    cCtx *C.vscf_key_provider_t /*ct2*/
}
const (
    /*
    * Length of the public key identifier.
    */
    KeyProviderKeyIdLen uint = 8
)

/* Handle underlying C context. */
func (obj *KeyProvider) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewKeyProvider() *KeyProvider {
    ctx := C.vscf_key_provider_new()
    obj := &KeyProvider {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*KeyProvider).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKeyProviderWithCtx(ctx *C.vscf_key_provider_t /*ct2*/) *KeyProvider {
    obj := &KeyProvider {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*KeyProvider).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newKeyProviderCopy(ctx *C.vscf_key_provider_t /*ct2*/) *KeyProvider {
    obj := &KeyProvider {
        cCtx: C.vscf_key_provider_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*KeyProvider).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *KeyProvider) Delete() {
    if obj == nil {
        return
    }
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
    C.vscf_key_provider_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
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

    runtime.KeepAlive(obj)

    return nil
}

/*
* Setup parameters that is used during RSA key generation.
*/
func (obj *KeyProvider) SetRsaParams(bitlen uint) {
    C.vscf_key_provider_set_rsa_params(obj.cCtx, (C.size_t)(bitlen)/*pa10*/)

    runtime.KeepAlive(obj)

    return
}

/*
* Generate new private key with a given algorithm.
*/
func (obj *KeyProvider) GeneratePrivateKey(algId AlgId) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_key_provider_generate_private_key(obj.cCtx, C.vscf_alg_id_t(algId) /*pa7*/, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPrivateKey(proxyResult) /* r4 */
}

/*
* Generate new post-quantum private key with default algorithms.
* Note, that a post-quantum key combines classic private keys
* alongside with post-quantum private keys.
* Current structure is "compound private key" is:
* - cipher private key is "hybrid private key" where:
* - first key is a classic private key;
* - second key is a post-quantum private key;
* - signer private key "hybrid private key" where:
* - first key is a classic private key;
* - second key is a post-quantum private key.
*/
func (obj *KeyProvider) GeneratePostQuantumPrivateKey() (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_key_provider_generate_post_quantum_private_key(obj.cCtx, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPrivateKey(proxyResult) /* r4 */
}

/*
* Generate new compound private key with given algorithms.
*/
func (obj *KeyProvider) GenerateCompoundPrivateKey(cipherAlgId AlgId, signerAlgId AlgId) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_key_provider_generate_compound_private_key(obj.cCtx, C.vscf_alg_id_t(cipherAlgId) /*pa7*/, C.vscf_alg_id_t(signerAlgId) /*pa7*/, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPrivateKey(proxyResult) /* r4 */
}

/*
* Generate new hybrid private key with given algorithms.
*/
func (obj *KeyProvider) GenerateHybridPrivateKey(firstKeyAlgId AlgId, secondKeyAlgId AlgId) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_key_provider_generate_hybrid_private_key(obj.cCtx, C.vscf_alg_id_t(firstKeyAlgId) /*pa7*/, C.vscf_alg_id_t(secondKeyAlgId) /*pa7*/, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPrivateKey(proxyResult) /* r4 */
}

/*
* Generate new compound private key with nested hybrid private keys.
*
* Note, second key algorithm identifiers can be NONE, in this case,
* a regular key will be crated instead of a hybrid key.
*/
func (obj *KeyProvider) GenerateCompoundHybridPrivateKey(cipherFirstKeyAlgId AlgId, cipherSecondKeyAlgId AlgId, signerFirstKeyAlgId AlgId, signerSecondKeyAlgId AlgId) (PrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_key_provider_generate_compound_hybrid_private_key(obj.cCtx, C.vscf_alg_id_t(cipherFirstKeyAlgId) /*pa7*/, C.vscf_alg_id_t(cipherSecondKeyAlgId) /*pa7*/, C.vscf_alg_id_t(signerFirstKeyAlgId) /*pa7*/, C.vscf_alg_id_t(signerSecondKeyAlgId) /*pa7*/, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

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

    runtime.KeepAlive(obj)

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

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapPublicKey(proxyResult) /* r4 */
}

/*
* Calculate buffer size enough to hold exported public key.
*
* Precondition: public key must be exportable.
*/
func (obj *KeyProvider) ExportedPublicKeyLen(publicKey PublicKey) uint {
    proxyResult := /*pr4*/C.vscf_key_provider_exported_public_key_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return uint(proxyResult) /* r9 */
}

/*
* Export given public key to the PKCS#8 DER format.
*
* Precondition: public key must be exportable.
*/
func (obj *KeyProvider) ExportPublicKey(publicKey PublicKey) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.ExportedPublicKeyLen(publicKey.(PublicKey)) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()


    proxyResult := /*pr4*/C.vscf_key_provider_export_public_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())), outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return outBuf.getData() /* r7 */, nil
}

/*
* Calculate buffer size enough to hold exported private key.
*
* Precondition: private key must be exportable.
*/
func (obj *KeyProvider) ExportedPrivateKeyLen(privateKey PrivateKey) uint {
    proxyResult := /*pr4*/C.vscf_key_provider_exported_private_key_len(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return uint(proxyResult) /* r9 */
}

/*
* Export given private key to the PKCS#8 or SEC1 DER format.
*
* Precondition: private key must be exportable.
*/
func (obj *KeyProvider) ExportPrivateKey(privateKey PrivateKey) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.ExportedPrivateKeyLen(privateKey.(PrivateKey)) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()


    proxyResult := /*pr4*/C.vscf_key_provider_export_private_key(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), outBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(privateKey)

    return outBuf.getData() /* r7 */, nil
}

/*
* Calculate identifier based on the given public key or private key.
*
* Note, that public key identifier equals to the private key identifier.
*/
func (obj *KeyProvider) CalculateKeyId(key Key) ([]byte, error) {
    keyIdBuf, keyIdBufErr := newBuffer(int(KeyProviderKeyIdLen /* lg4 */))
    if keyIdBufErr != nil {
        return nil, keyIdBufErr
    }
    defer keyIdBuf.delete()


    proxyResult := /*pr4*/C.vscf_key_provider_calculate_key_id(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(key.Ctx())), keyIdBuf.ctx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(key)

    return keyIdBuf.getData() /* r7 */, nil
}
