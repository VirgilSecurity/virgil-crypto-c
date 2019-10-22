package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

/*
* Handles ECC private key.
*/
type EccPrivateKey struct {
    IKey
    IPrivateKey
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this EccPrivateKey) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewEccPrivateKey () *EccPrivateKey {
    ctx := C.vscf_ecc_private_key_new()
    return &EccPrivateKey {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewEccPrivateKeyWithCtx (ctx *C.vscf_impl_t) *EccPrivateKey {
    return &EccPrivateKey {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewEccPrivateKeyCopy (ctx *C.vscf_impl_t) *EccPrivateKey {
    return &EccPrivateKey {
        ctx: C.vscf_ecc_private_key_shallow_copy(ctx),
    }
}

/*
* Algorithm identifier the key belongs to.
*/
func (this EccPrivateKey) AlgId () AlgId {
    proxyResult := C.vscf_ecc_private_key_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (this EccPrivateKey) AlgInfo () IAlgInfo {
    proxyResult := C.vscf_ecc_private_key_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Length of the key in bytes.
*/
func (this EccPrivateKey) Len () int32 {
    proxyResult := C.vscf_ecc_private_key_len(this.ctx)

    return proxyResult //r9
}

/*
* Length of the key in bits.
*/
func (this EccPrivateKey) Bitlen () int32 {
    proxyResult := C.vscf_ecc_private_key_bitlen(this.ctx)

    return proxyResult //r9
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (this EccPrivateKey) IsValid () bool {
    proxyResult := C.vscf_ecc_private_key_is_valid(this.ctx)

    return proxyResult //r9
}

/*
* Extract public key from the private key.
*/
func (this EccPrivateKey) ExtractPublicKey () IPublicKey {
    proxyResult := C.vscf_ecc_private_key_extract_public_key(this.ctx)

    return FoundationImplementationWrapIPublicKey(proxyResult) /* r4 */
}
