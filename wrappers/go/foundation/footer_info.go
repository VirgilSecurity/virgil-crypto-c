package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handle meta information about footer.
*/
type FooterInfo struct {
    cCtx *C.vscf_footer_info_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *FooterInfo) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewFooterInfo() *FooterInfo {
    ctx := C.vscf_footer_info_new()
    obj := &FooterInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*FooterInfo).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newFooterInfoWithCtx(ctx *C.vscf_footer_info_t /*ct2*/) *FooterInfo {
    obj := &FooterInfo {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*FooterInfo).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newFooterInfoCopy(ctx *C.vscf_footer_info_t /*ct2*/) *FooterInfo {
    obj := &FooterInfo {
        cCtx: C.vscf_footer_info_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*FooterInfo).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *FooterInfo) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *FooterInfo) delete() {
    C.vscf_footer_info_delete(obj.cCtx)
}

/*
* Retrun true if signed data info present.
*/
func (obj *FooterInfo) HasSignedDataInfo() bool {
    proxyResult := /*pr4*/C.vscf_footer_info_has_signed_data_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return signed data info.
*/
func (obj *FooterInfo) SignedDataInfo() *SignedDataInfo {
    proxyResult := /*pr4*/C.vscf_footer_info_signed_data_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return newSignedDataInfoCopy(proxyResult) /* r5 */
}

/*
* Set data size.
*/
func (obj *FooterInfo) SetDataSize(dataSize int) {
    C.vscf_footer_info_set_data_size(obj.cCtx, (C.size_t)(dataSize)/*pa10*/)

    runtime.KeepAlive(obj)

    return
}

/*
* Return data size.
*/
func (obj *FooterInfo) DataSize() int {
    proxyResult := /*pr4*/C.vscf_footer_info_data_size(obj.cCtx)

    runtime.KeepAlive(obj)

    return int(proxyResult) /* r9 */
}
