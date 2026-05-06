package phe

// #include <virgil/crypto/phe/vsce_phe_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import foundation "virgil/foundation"


/*
* Implements wrap rotation.
*/
type UokmsWrapRotation struct {
    cCtx *C.vsce_uokms_wrap_rotation_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *UokmsWrapRotation) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewUokmsWrapRotation() *UokmsWrapRotation {
    ctx := C.vsce_uokms_wrap_rotation_new()
    obj := &UokmsWrapRotation {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*UokmsWrapRotation).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newUokmsWrapRotationWithCtx(ctx *C.vsce_uokms_wrap_rotation_t /*ct2*/) *UokmsWrapRotation {
    obj := &UokmsWrapRotation {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*UokmsWrapRotation).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newUokmsWrapRotationCopy(ctx *C.vsce_uokms_wrap_rotation_t /*ct2*/) *UokmsWrapRotation {
    obj := &UokmsWrapRotation {
        cCtx: C.vsce_uokms_wrap_rotation_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*UokmsWrapRotation).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *UokmsWrapRotation) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *UokmsWrapRotation) delete() {
    C.vsce_uokms_wrap_rotation_delete(obj.cCtx)
}

/*
* Random used for crypto operations to make them const-time
*/
func (obj *UokmsWrapRotation) SetOperationRandom(operationRandom foundation.Random) {
    C.vsce_uokms_wrap_rotation_release_operation_random(obj.cCtx)
    C.vsce_uokms_wrap_rotation_use_operation_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(operationRandom.Ctx())))

    runtime.KeepAlive(operationRandom)
    runtime.KeepAlive(obj)
}

/*
* Setups dependencies with default values.
*/
func (obj *UokmsWrapRotation) SetupDefaults() error {
    proxyResult := /*pr4*/C.vsce_uokms_wrap_rotation_setup_defaults(obj.cCtx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Sets update token. Should be called only once and before any other function
*/
func (obj *UokmsWrapRotation) SetUpdateToken(updateToken []byte) error {
    updateTokenData := helperWrapData (updateToken)

    proxyResult := /*pr4*/C.vsce_uokms_wrap_rotation_set_update_token(obj.cCtx, updateTokenData)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Updates EnrollmentRecord using server's update token
*/
func (obj *UokmsWrapRotation) UpdateWrap(wrap []byte) ([]byte, error) {
    newWrapBuf, newWrapBufErr := newBuffer(int(PheCommonPhePublicKeyLength /* lg4 */))
    if newWrapBufErr != nil {
        return nil, newWrapBufErr
    }
    defer newWrapBuf.delete()
    wrapData := helperWrapData (wrap)

    proxyResult := /*pr4*/C.vsce_uokms_wrap_rotation_update_wrap(obj.cCtx, wrapData, newWrapBuf.ctx)

    err := PheErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return newWrapBuf.getData() /* r7 */, nil
}
