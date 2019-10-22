package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

type MessageInfoCustomParams struct {
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this MessageInfoCustomParams) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewMessageInfoCustomParams () *MessageInfoCustomParams {
    ctx := C.vscf_message_info_custom_params_new()
    return &MessageInfoCustomParams {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessageInfoCustomParamsWithCtx (ctx *C.vscf_impl_t) *MessageInfoCustomParams {
    return &MessageInfoCustomParams {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessageInfoCustomParamsCopy (ctx *C.vscf_impl_t) *MessageInfoCustomParams {
    return &MessageInfoCustomParams {
        ctx: C.vscf_message_info_custom_params_shallow_copy(ctx),
    }
}

func (this MessageInfoCustomParams) getOfIntType () int32 {
    return 1
}

func (this MessageInfoCustomParams) getOfStringType () int32 {
    return 2
}

func (this MessageInfoCustomParams) getOfDataType () int32 {
    return 3
}

/*
* Add custom parameter with integer value.
*/
func (this MessageInfoCustomParams) AddInt (key []byte, value int32) {
    C.vscf_message_info_custom_params_add_int(this.ctx, WrapData(key), value)
}

/*
* Add custom parameter with UTF8 string value.
*/
func (this MessageInfoCustomParams) AddString (key []byte, value []byte) {
    C.vscf_message_info_custom_params_add_string(this.ctx, WrapData(key), WrapData(value))
}

/*
* Add custom parameter with octet string value.
*/
func (this MessageInfoCustomParams) AddData (key []byte, value []byte) {
    C.vscf_message_info_custom_params_add_data(this.ctx, WrapData(key), WrapData(value))
}

/*
* Remove all parameters.
*/
func (this MessageInfoCustomParams) Clear () {
    C.vscf_message_info_custom_params_clear(this.ctx)
}

/*
* Return custom parameter with integer value.
*/
func (this MessageInfoCustomParams) FindInt (key []byte) int32 {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_message_info_custom_params_find_int(this.ctx, WrapData(key), &error)

    FoundationErrorHandleStatus(error.status)

    return proxyResult //r9
}

/*
* Return custom parameter with UTF8 string value.
*/
func (this MessageInfoCustomParams) FindString (key []byte) []byte {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_message_info_custom_params_find_string(this.ctx, WrapData(key), &error)

    FoundationErrorHandleStatus(error.status)

    return ExtractData(proxyResult) /* r1 */
}

/*
* Return custom parameter with octet string value.
*/
func (this MessageInfoCustomParams) FindData (key []byte) []byte {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_message_info_custom_params_find_data(this.ctx, WrapData(key), &error)

    FoundationErrorHandleStatus(error.status)

    return ExtractData(proxyResult) /* r1 */
}

/*
* Return true if at least one param exists.
*/
func (this MessageInfoCustomParams) HasParams () bool {
    proxyResult := C.vscf_message_info_custom_params_has_params(this.ctx)

    return proxyResult //r9
}
