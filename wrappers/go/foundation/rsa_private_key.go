package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

/*
* Handles RSA private key.
*/
type RsaPrivateKey struct {
    IKey
    IPrivateKey
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this RsaPrivateKey) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewRsaPrivateKey () *RsaPrivateKey {
    ctx := C.vscf_rsa_private_key_new()
    return &RsaPrivateKey {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewRsaPrivateKeyWithCtx (ctx *C.vscf_impl_t) *RsaPrivateKey {
    return &RsaPrivateKey {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewRsaPrivateKeyCopy (ctx *C.vscf_impl_t) *RsaPrivateKey {
    return &RsaPrivateKey {
        ctx: C.vscf_rsa_private_key_shallow_copy(ctx),
    }
}

/*
* Algorithm identifier the key belongs to.
*/
func (this RsaPrivateKey) AlgId () AlgId {
    proxyResult := C.vscf_rsa_private_key_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (this RsaPrivateKey) AlgInfo () IAlgInfo {
    proxyResult := C.vscf_rsa_private_key_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Length of the key in bytes.
*/
func (this RsaPrivateKey) Len () int32 {
    proxyResult := C.vscf_rsa_private_key_len(this.ctx)

    return proxyResult //r9
}

/*
* Length of the key in bits.
*/
func (this RsaPrivateKey) Bitlen () int32 {
    proxyResult := C.vscf_rsa_private_key_bitlen(this.ctx)

    return proxyResult //r9
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (this RsaPrivateKey) IsValid () bool {
    proxyResult := C.vscf_rsa_private_key_is_valid(this.ctx)

    return proxyResult //r9
}

/*
* Extract public key from the private key.
*/
func (this RsaPrivateKey) ExtractPublicKey () IPublicKey {
    proxyResult := C.vscf_rsa_private_key_extract_public_key(this.ctx)

    return FoundationImplementationWrapIPublicKey(proxyResult) /* r4 */
}
