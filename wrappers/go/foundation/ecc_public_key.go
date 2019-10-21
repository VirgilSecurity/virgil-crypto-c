package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"

/*
* Handles ECC public key.
*/
type EccPublicKey struct {
    IKey
    IPublicKey
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this EccPublicKey) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewEccPublicKey () *EccPublicKey {
    ctx := C.vscf_ecc_public_key_new()
    return &EccPublicKey {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewEccPublicKeyWithCtx (ctx *C.vscf_impl_t) *EccPublicKey {
    return &EccPublicKey {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewEccPublicKeyCopy (ctx *C.vscf_impl_t) *EccPublicKey {
    return &EccPublicKey {
        ctx: C.vscf_ecc_public_key_shallow_copy(ctx),
    }
}

/*
* Algorithm identifier the key belongs to.
*/
func (this EccPublicKey) AlgId () AlgId {
    proxyResult := C.vscf_ecc_public_key_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (this EccPublicKey) AlgInfo () IAlgInfo {
    proxyResult := C.vscf_ecc_public_key_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Length of the key in bytes.
*/
func (this EccPublicKey) Len () int32 {
    proxyResult := C.vscf_ecc_public_key_len(this.ctx)

    return proxyResult //r9
}

/*
* Length of the key in bits.
*/
func (this EccPublicKey) Bitlen () int32 {
    proxyResult := C.vscf_ecc_public_key_bitlen(this.ctx)

    return proxyResult //r9
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (this EccPublicKey) IsValid () bool {
    proxyResult := C.vscf_ecc_public_key_is_valid(this.ctx)

    return proxyResult //r9
}
