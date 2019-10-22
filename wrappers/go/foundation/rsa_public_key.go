package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

/*
* Handles RSA public key.
*/
type RsaPublicKey struct {
    IKey
    IPublicKey
    ctx *C.vscf_impl_t
}

/*
* Return public key exponent.
*/
func (this RsaPublicKey) KeyExponent () int32 {
    proxyResult := C.vscf_rsa_public_key_key_exponent(this.ctx)

    return proxyResult //r9
}

/* Handle underlying C context. */
func (this RsaPublicKey) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewRsaPublicKey () *RsaPublicKey {
    ctx := C.vscf_rsa_public_key_new()
    return &RsaPublicKey {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewRsaPublicKeyWithCtx (ctx *C.vscf_impl_t) *RsaPublicKey {
    return &RsaPublicKey {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewRsaPublicKeyCopy (ctx *C.vscf_impl_t) *RsaPublicKey {
    return &RsaPublicKey {
        ctx: C.vscf_rsa_public_key_shallow_copy(ctx),
    }
}

/*
* Algorithm identifier the key belongs to.
*/
func (this RsaPublicKey) AlgId () AlgId {
    proxyResult := C.vscf_rsa_public_key_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (this RsaPublicKey) AlgInfo () IAlgInfo {
    proxyResult := C.vscf_rsa_public_key_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Length of the key in bytes.
*/
func (this RsaPublicKey) Len () int32 {
    proxyResult := C.vscf_rsa_public_key_len(this.ctx)

    return proxyResult //r9
}

/*
* Length of the key in bits.
*/
func (this RsaPublicKey) Bitlen () int32 {
    proxyResult := C.vscf_rsa_public_key_bitlen(this.ctx)

    return proxyResult //r9
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (this RsaPublicKey) IsValid () bool {
    proxyResult := C.vscf_rsa_public_key_is_valid(this.ctx)

    return proxyResult //r9
}
