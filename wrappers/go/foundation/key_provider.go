package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

/*
* Provide functionality for private key generation and importing that
* relies on the software default implementations.
*/
type KeyProvider struct {
    cCtx *C.vscf_key_provider_t /*ct2*/
}

/* Handle underlying C context. */
func (this KeyProvider) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
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

/// Release underlying C context.
func (this KeyProvider) close () {
    C.vscf_key_provider_delete(this.cCtx)
}

func (this KeyProvider) SetRandom (random IRandom) {
    C.vscf_key_provider_release_random(this.cCtx)
    C.vscf_key_provider_use_random(this.cCtx, (*C.vscf_impl_t)(random.ctx()))
}

func (this KeyProvider) SetEcies (ecies Ecies) {
    C.vscf_key_provider_release_ecies(this.cCtx)
    C.vscf_key_provider_use_ecies(this.cCtx, (*C.vscf_ecies_t)(ecies.ctx()))
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this KeyProvider) SetupDefaults () error {
    proxyResult := /*pr4*/C.vscf_key_provider_setup_defaults(this.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Setup parameters that is used during RSA key generation.
*/
func (this KeyProvider) SetRsaParams (bitlen uint32) {
    C.vscf_key_provider_set_rsa_params(this.cCtx, (C.size_t)(bitlen)/*pa10*/)

    return
}

/*
* Generate new private key from the given id.
*/
func (this KeyProvider) GeneratePrivateKey (algId AlgId) (IPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    proxyResult := /*pr4*/C.vscf_key_provider_generate_private_key(this.cCtx, C.vscf_alg_id_t(algId) /*pa7*/, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return FoundationImplementationWrapIPrivateKey(proxyResult) /* r4 */
}

/*
* Import private key from the PKCS#8 format.
*/
func (this KeyProvider) ImportPrivateKey (keyData []byte) (IPrivateKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    keyDataData := C.vsc_data((*C.uint8_t)(&keyData[0]), C.size_t(len(keyData)))

    proxyResult := /*pr4*/C.vscf_key_provider_import_private_key(this.cCtx, keyDataData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return FoundationImplementationWrapIPrivateKey(proxyResult) /* r4 */
}

/*
* Import public key from the PKCS#8 format.
*/
func (this KeyProvider) ImportPublicKey (keyData []byte) (IPublicKey, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    keyDataData := C.vsc_data((*C.uint8_t)(&keyData[0]), C.size_t(len(keyData)))

    proxyResult := /*pr4*/C.vscf_key_provider_import_public_key(this.cCtx, keyDataData, &error)

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
func (this KeyProvider) ExportedPublicKeyLen (publicKey IPublicKey) uint32 {
    proxyResult := /*pr4*/C.vscf_key_provider_exported_public_key_len(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Export given public key to the PKCS#8 DER format.
*
* Precondition: public key must be exportable.
*/
func (this KeyProvider) ExportPublicKey (publicKey IPublicKey) ([]byte, error) {
    outCount := C.ulong(this.ExportedPublicKeyLen(publicKey.(IPublicKey)) /* lg2 */)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)


    proxyResult := /*pr4*/C.vscf_key_provider_export_public_key(this.cCtx, (*C.vscf_impl_t)(publicKey.ctx()), outBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */, nil
}

/*
* Calculate buffer size enough to hold exported private key.
*
* Precondition: private key must be exportable.
*/
func (this KeyProvider) ExportedPrivateKeyLen (privateKey IPrivateKey) uint32 {
    proxyResult := /*pr4*/C.vscf_key_provider_exported_private_key_len(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Export given private key to the PKCS#8 or SEC1 DER format.
*
* Precondition: private key must be exportable.
*/
func (this KeyProvider) ExportPrivateKey (privateKey IPrivateKey) ([]byte, error) {
    outCount := C.ulong(this.ExportedPrivateKeyLen(privateKey.(IPrivateKey)) /* lg2 */)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)


    proxyResult := /*pr4*/C.vscf_key_provider_export_private_key(this.cCtx, (*C.vscf_impl_t)(privateKey.ctx()), outBuf)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */, nil
}
