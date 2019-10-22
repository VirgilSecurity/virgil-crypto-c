package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Handles interchangeable public key representation.
*/
type RawPublicKey struct {
    IKey
    IPublicKey
    ctx *C.vscf_impl_t
}

/*
* Return key data.
*/
func (this RawPublicKey) Data () []byte {
    proxyResult := C.vscf_raw_public_key_data(this.ctx)

    return ExtractData(proxyResult) /* r1 */
}

/* Handle underlying C context. */
func (this RawPublicKey) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewRawPublicKey () *RawPublicKey {
    ctx := C.vscf_raw_public_key_new()
    return &RawPublicKey {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewRawPublicKeyWithCtx (ctx *C.vscf_impl_t) *RawPublicKey {
    return &RawPublicKey {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewRawPublicKeyCopy (ctx *C.vscf_impl_t) *RawPublicKey {
    return &RawPublicKey {
        ctx: C.vscf_raw_public_key_shallow_copy(ctx),
    }
}

/*
* Algorithm identifier the key belongs to.
*/
func (this RawPublicKey) AlgId () AlgId {
    proxyResult := C.vscf_raw_public_key_alg_id(this.ctx)

    return AlgId(proxyResult) /* r8 */
}

/*
* Return algorithm information that can be used for serialization.
*/
func (this RawPublicKey) AlgInfo () IAlgInfo {
    proxyResult := C.vscf_raw_public_key_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}

/*
* Length of the key in bytes.
*/
func (this RawPublicKey) Len () int32 {
    proxyResult := C.vscf_raw_public_key_len(this.ctx)

    return proxyResult //r9
}

/*
* Length of the key in bits.
*/
func (this RawPublicKey) Bitlen () int32 {
    proxyResult := C.vscf_raw_public_key_bitlen(this.ctx)

    return proxyResult //r9
}

/*
* Check that key is valid.
* Note, this operation can be slow.
*/
func (this RawPublicKey) IsValid () bool {
    proxyResult := C.vscf_raw_public_key_is_valid(this.ctx)

    return proxyResult //r9
}
