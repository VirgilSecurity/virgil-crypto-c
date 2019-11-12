package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* Handle meta information about signed data.
*/
type SignedDataInfo struct {
    cCtx *C.vscf_signed_data_info_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *SignedDataInfo) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewSignedDataInfo () *SignedDataInfo {
    ctx := C.vscf_signed_data_info_new()
    return &SignedDataInfo {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSignedDataInfoWithCtx (ctx *C.vscf_signed_data_info_t /*ct2*/) *SignedDataInfo {
    return &SignedDataInfo {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSignedDataInfoCopy (ctx *C.vscf_signed_data_info_t /*ct2*/) *SignedDataInfo {
    return &SignedDataInfo {
        cCtx: C.vscf_signed_data_info_shallow_copy(ctx),
    }
}

/*
* Release underlying C context.
*/
func (obj *SignedDataInfo) Delete () {
    C.vscf_signed_data_info_delete(obj.cCtx)
}

/*
* Set information about algorithm that was used to produce data digest.
*/
func (obj *SignedDataInfo) SetHashAlgInfo (hashAlgInfo IAlgInfo) {
    hashAlgInfoCopy := C.vscf_impl_shallow_copy((*C.vscf_impl_t)(hashAlgInfo.ctx()))

    C.vscf_signed_data_info_set_hash_alg_info(obj.cCtx, &hashAlgInfoCopy)

    return
}

/*
* Return information about algorithm that was used to produce data digest.
*/
func (obj *SignedDataInfo) HashAlgInfo () (IAlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_signed_data_info_hash_alg_info(obj.cCtx)

    return FoundationImplementationWrapIAlgInfo(proxyResult) /* r4 */
}
