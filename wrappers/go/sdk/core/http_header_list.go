package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"

/*
* Handles a list of "http header" class objects.
 */
type HttpHeaderList struct {
	cCtx *C.vssc_http_header_list_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *HttpHeaderList) Ctx() uintptr {
	return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewHttpHeaderList() *HttpHeaderList {
	ctx := C.vssc_http_header_list_new()
	obj := &HttpHeaderList{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*HttpHeaderList).Delete)
	return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewHttpHeaderListWithCtx(pointer unsafe.Pointer) *HttpHeaderList {
	ctx := (*C.vssc_http_header_list_t /*ct2*/)(pointer)
	obj := &HttpHeaderList{
		cCtx: ctx,
	}
	runtime.SetFinalizer(obj, (*HttpHeaderList).Delete)
	return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
 */
func NewHttpHeaderListCopy(pointer unsafe.Pointer) *HttpHeaderList {
	ctx := (*C.vssc_http_header_list_t /*ct2*/)(pointer)
	obj := &HttpHeaderList{
		cCtx: C.vssc_http_header_list_shallow_copy(ctx),
	}
	runtime.SetFinalizer(obj, (*HttpHeaderList).Delete)
	return obj
}

/*
* Release underlying C context.
 */
func (obj *HttpHeaderList) Delete() {
	if obj == nil {
		return
	}
	runtime.SetFinalizer(obj, nil)
	obj.delete()
}

/*
* Release underlying C context.
 */
func (obj *HttpHeaderList) delete() {
	C.vssc_http_header_list_delete(obj.cCtx)
}

/*
* Return true if given list has item.
 */
func (obj *HttpHeaderList) HasItem() bool {
	proxyResult := /*pr4*/ C.vssc_http_header_list_has_item(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return list item.
 */
func (obj *HttpHeaderList) Item() *HttpHeader {
	proxyResult := /*pr4*/ C.vssc_http_header_list_item(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewHttpHeaderCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return true if list has next item.
 */
func (obj *HttpHeaderList) HasNext() bool {
	proxyResult := /*pr4*/ C.vssc_http_header_list_has_next(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return next list node if exists, or NULL otherwise.
 */
func (obj *HttpHeaderList) Next() *HttpHeaderList {
	proxyResult := /*pr4*/ C.vssc_http_header_list_next(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewHttpHeaderListCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return true if list has previous item.
 */
func (obj *HttpHeaderList) HasPrev() bool {
	proxyResult := /*pr4*/ C.vssc_http_header_list_has_prev(obj.cCtx)

	runtime.KeepAlive(obj)

	return bool(proxyResult) /* r9 */
}

/*
* Return previous list node if exists, or NULL otherwise.
 */
func (obj *HttpHeaderList) Prev() *HttpHeaderList {
	proxyResult := /*pr4*/ C.vssc_http_header_list_prev(obj.cCtx)

	runtime.KeepAlive(obj)

	return NewHttpHeaderListCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Remove all items.
 */
func (obj *HttpHeaderList) Clear() {
	C.vssc_http_header_list_clear(obj.cCtx)

	runtime.KeepAlive(obj)

	return
}

/*
* Find header by it's name.
 */
func (obj *HttpHeaderList) Find(name string) (string, error) {
	var error C.vssc_error_t
	C.vssc_error_reset(&error)
	nameChar := C.CString(name)
	defer C.free(unsafe.Pointer(nameChar))
	nameStr := C.vsc_str_from_str(nameChar)

	proxyResult := /*pr4*/ C.vssc_http_header_list_find(obj.cCtx, nameStr, &error)

	err := CoreSdkErrorHandleStatus(error.status)
	if err != nil {
		return "", err
	}

	runtime.KeepAlive(obj)

	runtime.KeepAlive(name)

	return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */, nil
}
