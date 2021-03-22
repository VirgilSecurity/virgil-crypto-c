package sdk_brainkey

// #include <virgil/sdk/brainkey/vssb_brainkey_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handles Brainkey hardened point returned by the service.
*/
type BrainkeyHardenedPoint struct {
    cCtx *C.vssb_brainkey_hardened_point_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *BrainkeyHardenedPoint) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewBrainkeyHardenedPoint() *BrainkeyHardenedPoint {
    ctx := C.vssb_brainkey_hardened_point_new()
    obj := &BrainkeyHardenedPoint {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*BrainkeyHardenedPoint).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewBrainkeyHardenedPointWithCtx(anyctx interface{}) *BrainkeyHardenedPoint {
    ctx, ok := anyctx. (*C.vssb_brainkey_hardened_point_t /*ct2*/)
    if !ok {
        return nil //TODO, &BrainkeySdkError{-1,"Cast error for struct BrainkeyHardenedPoint."}
    }
    obj := &BrainkeyHardenedPoint {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*BrainkeyHardenedPoint).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewBrainkeyHardenedPointCopy(anyctx interface{}) *BrainkeyHardenedPoint {
    ctx, ok := anyctx. (*C.vssb_brainkey_hardened_point_t /*ct2*/)
    if !ok {
        return nil //TODO, &BrainkeySdkError{-1,"Cast error for struct BrainkeyHardenedPoint."}
    }
    obj := &BrainkeyHardenedPoint {
        cCtx: C.vssb_brainkey_hardened_point_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*BrainkeyHardenedPoint).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *BrainkeyHardenedPoint) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *BrainkeyHardenedPoint) delete() {
    C.vssb_brainkey_hardened_point_delete(obj.cCtx)
}

/*
* Return Brainkey hardened point.
*/
func (obj *BrainkeyHardenedPoint) Value() []byte {
    proxyResult := /*pr4*/C.vssb_brainkey_hardened_point_value(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}
