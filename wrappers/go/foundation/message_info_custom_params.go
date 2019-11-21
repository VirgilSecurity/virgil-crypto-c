package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"


type MessageInfoCustomParams struct {
    cCtx *C.vscf_message_info_custom_params_t /*ct2*/
}
const (
    MessageInfoCustomParamsOfIntType uint32 = 1
    MessageInfoCustomParamsOfStringType uint32 = 2
    MessageInfoCustomParamsOfDataType uint32 = 3
)

/* Handle underlying C context. */
func (obj *MessageInfoCustomParams) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewMessageInfoCustomParams() *MessageInfoCustomParams {
    ctx := C.vscf_message_info_custom_params_new()
    obj := &MessageInfoCustomParams {
        cCtx: ctx,
    }
    //runtime.SetFinalizer(obj, func (o *MessageInfoCustomParams) {o.Delete()})
    runtime.SetFinalizer(obj, (*MessageInfoCustomParams).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newMessageInfoCustomParamsWithCtx(ctx *C.vscf_message_info_custom_params_t /*ct2*/) *MessageInfoCustomParams {
    obj := &MessageInfoCustomParams {
        cCtx: ctx,
    }
    //runtime.SetFinalizer(obj, func (o *MessageInfoCustomParams) {o.Delete()})
    runtime.SetFinalizer(obj, (*MessageInfoCustomParams).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newMessageInfoCustomParamsCopy(ctx *C.vscf_message_info_custom_params_t /*ct2*/) *MessageInfoCustomParams {
    obj := &MessageInfoCustomParams {
        cCtx: C.vscf_message_info_custom_params_shallow_copy(ctx),
    }
    //runtime.SetFinalizer(obj, func (o *MessageInfoCustomParams) {o.Delete()})
    runtime.SetFinalizer(obj, (*MessageInfoCustomParams).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *MessageInfoCustomParams) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *MessageInfoCustomParams) delete() {
    C.vscf_message_info_custom_params_delete(obj.cCtx)
}

/*
* Add custom parameter with integer value.
*/
func (obj *MessageInfoCustomParams) AddInt(key []byte, value int32) {
    keyData := helperWrapData (key)

    C.vscf_message_info_custom_params_add_int(obj.cCtx, keyData, (C.int32_t)(value)/*pa10*/)

    runtime.KeepAlive(obj)

    return
}

/*
* Add custom parameter with UTF8 string value.
*/
func (obj *MessageInfoCustomParams) AddString(key []byte, value []byte) {
    keyData := helperWrapData (key)
    valueData := helperWrapData (value)

    C.vscf_message_info_custom_params_add_string(obj.cCtx, keyData, valueData)

    runtime.KeepAlive(obj)

    return
}

/*
* Add custom parameter with octet string value.
*/
func (obj *MessageInfoCustomParams) AddData(key []byte, value []byte) {
    keyData := helperWrapData (key)
    valueData := helperWrapData (value)

    C.vscf_message_info_custom_params_add_data(obj.cCtx, keyData, valueData)

    runtime.KeepAlive(obj)

    return
}

/*
* Remove all parameters.
*/
func (obj *MessageInfoCustomParams) Clear() {
    C.vscf_message_info_custom_params_clear(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Return custom parameter with integer value.
*/
func (obj *MessageInfoCustomParams) FindInt(key []byte) (int32, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    keyData := helperWrapData (key)

    proxyResult := /*pr4*/C.vscf_message_info_custom_params_find_int(obj.cCtx, keyData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return 0, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(error)

    return int32(proxyResult) /* r9 */, nil
}

/*
* Return custom parameter with UTF8 string value.
*/
func (obj *MessageInfoCustomParams) FindString(key []byte) ([]byte, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    keyData := helperWrapData (key)

    proxyResult := /*pr4*/C.vscf_message_info_custom_params_find_string(obj.cCtx, keyData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(error)

    return helperExtractData(proxyResult) /* r1 */, nil
}

/*
* Return custom parameter with octet string value.
*/
func (obj *MessageInfoCustomParams) FindData(key []byte) ([]byte, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    keyData := helperWrapData (key)

    proxyResult := /*pr4*/C.vscf_message_info_custom_params_find_data(obj.cCtx, keyData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(error)

    return helperExtractData(proxyResult) /* r1 */, nil
}

/*
* Return true if at least one param exists.
*/
func (obj *MessageInfoCustomParams) HasParams() bool {
    proxyResult := /*pr4*/C.vscf_message_info_custom_params_has_params(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}
