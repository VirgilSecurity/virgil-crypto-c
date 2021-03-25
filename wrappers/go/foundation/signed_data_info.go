package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handle meta information about signed data.
*/
type SignedDataInfo struct {
    cCtx *C.vscf_signed_data_info_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *SignedDataInfo) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewSignedDataInfo() *SignedDataInfo {
    ctx := C.vscf_signed_data_info_new()
    obj := &SignedDataInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*SignedDataInfo).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSignedDataInfoWithCtx(pointer unsafe.Pointer) *SignedDataInfo {
    ctx := (*C.vscf_signed_data_info_t /*ct2*/)(pointer)
    obj := &SignedDataInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*SignedDataInfo).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewSignedDataInfoCopy(pointer unsafe.Pointer) *SignedDataInfo {
    ctx := (*C.vscf_signed_data_info_t /*ct2*/)(pointer)
    obj := &SignedDataInfo {
        cCtx: C.vscf_signed_data_info_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*SignedDataInfo).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *SignedDataInfo) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *SignedDataInfo) delete() {
    C.vscf_signed_data_info_delete(obj.cCtx)
}

/*
* Return information about algorithm that was used to produce data digest.
*/
func (obj *SignedDataInfo) HashAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_signed_data_info_hash_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return ImplementationWrapAlgInfoCopy(unsafe.Pointer(proxyResult)) /* r4.1 */
}
