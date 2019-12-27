package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handles padding parameters and constraints.
*/
type PaddingParams struct {
    cCtx *C.vscf_padding_params_t /*ct2*/
}
const (
    PaddingParamsDefaultFrameMin uint32 = 32
    PaddingParamsDefaultFrame uint32 = 160
    PaddingParamsDefaultFrameMax uint32 = 256
)

/* Handle underlying C context. */
func (obj *PaddingParams) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewPaddingParams() *PaddingParams {
    ctx := C.vscf_padding_params_new()
    obj := &PaddingParams {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*PaddingParams).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPaddingParamsWithCtx(ctx *C.vscf_padding_params_t /*ct2*/) *PaddingParams {
    obj := &PaddingParams {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*PaddingParams).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newPaddingParamsCopy(ctx *C.vscf_padding_params_t /*ct2*/) *PaddingParams {
    obj := &PaddingParams {
        cCtx: C.vscf_padding_params_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*PaddingParams).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *PaddingParams) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *PaddingParams) delete() {
    C.vscf_padding_params_delete(obj.cCtx)
}

/*
* Build padding params with given constraints.
* Next formula can clarify what frame is: padding_length = data_length MOD frame
*/
func NewPaddingParamsWithConstraints(frame uint32, frameMax uint32) *PaddingParams {
    proxyResult := /*pr4*/C.vscf_padding_params_new_with_constraints((C.size_t)(frame)/*pa10*/, (C.size_t)(frameMax)/*pa10*/)

    obj := &PaddingParams {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*PaddingParams).Delete)
    return obj
}

/*
* Return padding frame in bytes.
*/
func (obj *PaddingParams) Frame() uint32 {
    proxyResult := /*pr4*/C.vscf_padding_params_frame(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint32(proxyResult) /* r9 */
}

/*
* Return maximum padding frame in bytes.
*/
func (obj *PaddingParams) FrameMax() uint32 {
    proxyResult := /*pr4*/C.vscf_padding_params_frame_max(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint32(proxyResult) /* r9 */
}
