package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"

/*
* Handles HTTP header in a most generic way.
 */
type HttpHeader struct {
	cCtx *C.vssc_http_header_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *HttpHeader) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewHttpHeader() *HttpHeader {
	ctx := C.vssc_http_header_new()
	obj := &HttpHeader{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*HttpHeader).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewHttpHeaderWithCtx(anyctx interface{}) *HttpHeader {
	ctx, ok := anyctx.(*C.vssc_http_header_t /*ct2*/)
	if !ok {
		return nil //TODO, &CoreSdkError{-1,"Cast error for struct HttpHeader."}
	}
	obj := &HttpHeader{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*HttpHeader).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewHttpHeaderCopy(anyctx interface{}) *HttpHeader {
	ctx, ok := anyctx.(*C.vssc_http_header_t /*ct2*/)
	if !ok {
		return nil //TODO, &CoreSdkError{-1,"Cast error for struct HttpHeader."}
	}
	obj := &HttpHeader{
		cCtx: C.vssc_http_header_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*HttpHeader).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *HttpHeader) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *HttpHeader) delete() {
	C.vssc_http_header_delete(obj.cCtx)
}

/*
* Create fully defined HTTP header.
*
* Prerequisite: name is not empty.
* Prerequisite: value is not empty.
 */
func NewHttpHeaderWith(name string, value string) *HttpHeader {
	nameChar := C.CString(name)
	defer C.free(unsafe.Pointer(nameChar))
	nameStr := C.vsc_str_from_str(nameChar)
	valueChar := C.CString(value)
	defer C.free(unsafe.Pointer(valueChar))
	valueStr := C.vsc_str_from_str(valueChar)

	proxyResult := /*pr4*/ C.vssc_http_header_new_with(nameStr, valueStr)

	runtime.KeepAlive(name)

	runtime.KeepAlive(value)

	obj := &HttpHeader{
		cCtx: proxyResult,
	}
	runtime.SetFinalizer(obj, (*HttpHeader).Delete)
	return obj
}

/*
* Return HTTP header name.
 */
func (obj *HttpHeader) Name() string {
	proxyResult := /*pr4*/ C.vssc_http_header_name(obj.cCtx)

	runtime.KeepAlive(obj)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return HTTP header value.
 */
func (obj *HttpHeader) Value() string {
	proxyResult := /*pr4*/ C.vssc_http_header_value(obj.cCtx)

	runtime.KeepAlive(obj)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}
