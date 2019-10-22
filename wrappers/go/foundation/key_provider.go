package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Provide functionality for private key generation and importing that
* relies on the software default implementations.
*/
type KeyProvider struct {
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this KeyProvider) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewKeyProvider () *KeyProvider {
    ctx := C.vscf_key_provider_new()
    return &KeyProvider {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewKeyProviderWithCtx (ctx *C.vscf_impl_t) *KeyProvider {
    return &KeyProvider {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewKeyProviderCopy (ctx *C.vscf_impl_t) *KeyProvider {
    return &KeyProvider {
        ctx: C.vscf_key_provider_shallow_copy(ctx),
    }
}

func (this KeyProvider) SetRandom (random IRandom) {
    C.vscf_key_provider_release_random(this.ctx)
    C.vscf_key_provider_use_random(this.ctx, random.Ctx())
}

func (this KeyProvider) SetEcies (ecies Ecies) {
    C.vscf_key_provider_release_ecies(this.ctx)
    C.vscf_key_provider_use_ecies(this.ctx, ecies.Ctx())
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this KeyProvider) SetupDefaults () {
    proxyResult := C.vscf_key_provider_setup_defaults(this.ctx)

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Setup parameters that is used during RSA key generation.
*/
func (this KeyProvider) SetRsaParams (bitlen int32) {
    C.vscf_key_provider_set_rsa_params(this.ctx, bitlen)
}

/*
* Generate new private key from the given id.
*/
func (this KeyProvider) GeneratePrivateKey (algId AlgId) IPrivateKey {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_key_provider_generate_private_key(this.ctx, algId /*pa7*/, &error)

    FoundationErrorHandleStatus(error.status)

    return FoundationImplementationWrapIPrivateKey(proxyResult) /* r4 */
}

/*
* Import private key from the PKCS#8 format.
*/
func (this KeyProvider) ImportPrivateKey (keyData []byte) IPrivateKey {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_key_provider_import_private_key(this.ctx, WrapData(keyData), &error)

    FoundationErrorHandleStatus(error.status)

    return FoundationImplementationWrapIPrivateKey(proxyResult) /* r4 */
}

/*
* Import public key from the PKCS#8 format.
*/
func (this KeyProvider) ImportPublicKey (keyData []byte) IPublicKey {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_key_provider_import_public_key(this.ctx, WrapData(keyData), &error)

    FoundationErrorHandleStatus(error.status)

    return FoundationImplementationWrapIPublicKey(proxyResult) /* r4 */
}

/*
* Calculate buffer size enough to hold exported public key.
*
* Precondition: public key must be exportable.
*/
func (this KeyProvider) ExportedPublicKeyLen (publicKey IPublicKey) int32 {
    proxyResult := C.vscf_key_provider_exported_public_key_len(this.ctx, publicKey.Ctx())

    return proxyResult //r9
}

/*
* Export given public key to the PKCS#8 DER format.
*
* Precondition: public key must be exportable.
*/
func (this KeyProvider) ExportPublicKey (publicKey IPublicKey) []byte {
    outCount := this.ExportedPublicKeyLen(publicKey) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_key_provider_export_public_key(this.ctx, publicKey.Ctx(), outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}

/*
* Calculate buffer size enough to hold exported private key.
*
* Precondition: private key must be exportable.
*/
func (this KeyProvider) ExportedPrivateKeyLen (privateKey IPrivateKey) int32 {
    proxyResult := C.vscf_key_provider_exported_private_key_len(this.ctx, privateKey.Ctx())

    return proxyResult //r9
}

/*
* Export given private key to the PKCS#8 or SEC1 DER format.
*
* Precondition: private key must be exportable.
*/
func (this KeyProvider) ExportPrivateKey (privateKey IPrivateKey) []byte {
    outCount := this.ExportedPrivateKeyLen(privateKey) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    proxyResult := C.vscf_key_provider_export_private_key(this.ctx, privateKey.Ctx(), outBuf)

    FoundationErrorHandleStatus(proxyResult)

    return outBuf.GetData() /* r7 */
}
