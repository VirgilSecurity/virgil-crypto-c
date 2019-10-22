package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

/*
* Handle meta information about signed data.
*/
type SignedDataInfo struct {
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this SignedDataInfo) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewSignedDataInfo () *SignedDataInfo {
    ctx := C.vscf_signed_data_info_new()
    return &SignedDataInfo {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSignedDataInfoWithCtx (ctx *C.vscf_impl_t) *SignedDataInfo {
    return &SignedDataInfo {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSignedDataInfoCopy (ctx *C.vscf_impl_t) *SignedDataInfo {
    return &SignedDataInfo {
        ctx: C.vscf_signed_data_info_shallow_copy(ctx),
    }
}

/*
* Set information about algorithm that was used to produce data digest.
*/
func (this SignedDataInfo) SetHashAlgInfo (hashAlgInfo IAlgInfo) {
    hashAlgInfoCopy := C.vscf_impl_shallow_copy(hashAlgInfo.Ctx())

    C.vscf_signed_data_info_set_hash_alg_info(this.ctx, &hashAlgInfoCopy)
}

/*
* Return information about algorithm that was used to produce data digest.
*/
func (this SignedDataInfo) HashAlgInfo () IAlgInfo {
    proxyResult := C.vscf_signed_data_info_hash_alg_info(this.ctx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}
