package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"

type MessageInfoCustomParams struct {
    cCtx *C.vscf_message_info_custom_params_t /*ct2*/
}

/* Handle underlying C context. */
func (this MessageInfoCustomParams) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewMessageInfoCustomParams () *MessageInfoCustomParams {
    ctx := C.vscf_message_info_custom_params_new()
    return &MessageInfoCustomParams {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newMessageInfoCustomParamsWithCtx (ctx *C.vscf_message_info_custom_params_t /*ct2*/) *MessageInfoCustomParams {
    return &MessageInfoCustomParams {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newMessageInfoCustomParamsCopy (ctx *C.vscf_message_info_custom_params_t /*ct2*/) *MessageInfoCustomParams {
    return &MessageInfoCustomParams {
        cCtx: C.vscf_message_info_custom_params_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this MessageInfoCustomParams) close () {
    C.vscf_message_info_custom_params_delete(this.cCtx)
}

func MessageInfoCustomParamsGetOfIntType () uint32 {
    return 1
}

func MessageInfoCustomParamsGetOfStringType () uint32 {
    return 2
}

func MessageInfoCustomParamsGetOfDataType () uint32 {
    return 3
}

/*
* Add custom parameter with integer value.
*/
func (this MessageInfoCustomParams) AddInt (key []byte, value int32) {
    keyData := C.vsc_data((*C.uint8_t)(&key[0]), C.size_t(len(key)))

    C.vscf_message_info_custom_params_add_int(this.cCtx, keyData, (C.int32_t)(value)/*pa10*/)

    return
}

/*
* Add custom parameter with UTF8 string value.
*/
func (this MessageInfoCustomParams) AddString (key []byte, value []byte) {
    keyData := C.vsc_data((*C.uint8_t)(&key[0]), C.size_t(len(key)))
    valueData := C.vsc_data((*C.uint8_t)(&value[0]), C.size_t(len(value)))

    C.vscf_message_info_custom_params_add_string(this.cCtx, keyData, valueData)

    return
}

/*
* Add custom parameter with octet string value.
*/
func (this MessageInfoCustomParams) AddData (key []byte, value []byte) {
    keyData := C.vsc_data((*C.uint8_t)(&key[0]), C.size_t(len(key)))
    valueData := C.vsc_data((*C.uint8_t)(&value[0]), C.size_t(len(value)))

    C.vscf_message_info_custom_params_add_data(this.cCtx, keyData, valueData)

    return
}

/*
* Remove all parameters.
*/
func (this MessageInfoCustomParams) Clear () {
    C.vscf_message_info_custom_params_clear(this.cCtx)

    return
}

/*
* Return custom parameter with integer value.
*/
func (this MessageInfoCustomParams) FindInt (key []byte) (int32, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    keyData := C.vsc_data((*C.uint8_t)(&key[0]), C.size_t(len(key)))

    proxyResult := /*pr4*/C.vscf_message_info_custom_params_find_int(this.cCtx, keyData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return 0, err
    }

    return int32(proxyResult) /* r9 */, nil
}

/*
* Return custom parameter with UTF8 string value.
*/
func (this MessageInfoCustomParams) FindString (key []byte) ([]byte, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    keyData := C.vsc_data((*C.uint8_t)(&key[0]), C.size_t(len(key)))

    proxyResult := /*pr4*/C.vscf_message_info_custom_params_find_string(this.cCtx, keyData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return helperDataToBytes(proxyResult) /* r1 */, nil
}

/*
* Return custom parameter with octet string value.
*/
func (this MessageInfoCustomParams) FindData (key []byte) ([]byte, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    keyData := C.vsc_data((*C.uint8_t)(&key[0]), C.size_t(len(key)))

    proxyResult := /*pr4*/C.vscf_message_info_custom_params_find_data(this.cCtx, keyData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return helperDataToBytes(proxyResult) /* r1 */, nil
}

/*
* Return true if at least one param exists.
*/
func (this MessageInfoCustomParams) HasParams () bool {
    proxyResult := /*pr4*/C.vscf_message_info_custom_params_has_params(this.cCtx)

    return bool(proxyResult) /* r9 */
}
