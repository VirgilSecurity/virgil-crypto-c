package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Handles HTTP request in a most generic way.
*/
type HttpRequest struct {
    cCtx *C.vssc_http_request_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *HttpRequest) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewHttpRequest() *HttpRequest {
    ctx := C.vssc_http_request_new()
    obj := &HttpRequest {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*HttpRequest).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewHttpRequestWithCtx(pointer unsafe.Pointer) *HttpRequest {
    ctx := (*C.vssc_http_request_t /*ct2*/)(pointer)
    obj := &HttpRequest {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*HttpRequest).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewHttpRequestCopy(pointer unsafe.Pointer) *HttpRequest {
    ctx := (*C.vssc_http_request_t /*ct2*/)(pointer)
    obj := &HttpRequest {
        cCtx: C.vssc_http_request_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*HttpRequest).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *HttpRequest) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *HttpRequest) delete() {
    C.vssc_http_request_delete(obj.cCtx)
}

/*
* Create HTTP request with URL.
*/
func NewHttpRequestWithUrl(method string, url string) *HttpRequest {
    methodChar := C.CString(method)
    defer C.free(unsafe.Pointer(methodChar))
    methodStr := C.vsc_str_from_str(methodChar)
    urlChar := C.CString(url)
    defer C.free(unsafe.Pointer(urlChar))
    urlStr := C.vsc_str_from_str(urlChar)

    proxyResult := /*pr4*/C.vssc_http_request_new_with_url(methodStr, urlStr)

    runtime.KeepAlive(method)

    runtime.KeepAlive(url)

    obj := &HttpRequest {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*HttpRequest).Delete)
    return obj
}

/*
* Create HTTP request with URL and body.
*/
func NewHttpRequestWithBody(method string, url string, body []byte) *HttpRequest {
    methodChar := C.CString(method)
    defer C.free(unsafe.Pointer(methodChar))
    methodStr := C.vsc_str_from_str(methodChar)
    urlChar := C.CString(url)
    defer C.free(unsafe.Pointer(urlChar))
    urlStr := C.vsc_str_from_str(urlChar)
    bodyData := helperWrapData (body)

    proxyResult := /*pr4*/C.vssc_http_request_new_with_body(methodStr, urlStr, bodyData)

    runtime.KeepAlive(method)

    runtime.KeepAlive(url)

    obj := &HttpRequest {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*HttpRequest).Delete)
    return obj
}

/*
* Add HTTP header.
*/
func (obj *HttpRequest) AddHeader(name string, value string) {
    nameChar := C.CString(name)
    defer C.free(unsafe.Pointer(nameChar))
    nameStr := C.vsc_str_from_str(nameChar)
    valueChar := C.CString(value)
    defer C.free(unsafe.Pointer(valueChar))
    valueStr := C.vsc_str_from_str(valueChar)

    C.vssc_http_request_add_header(obj.cCtx, nameStr, valueStr)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(name)

    runtime.KeepAlive(value)

    return
}

/*
* Return HTTP method.
*/
func (obj *HttpRequest) Method() string {
    proxyResult := /*pr4*/C.vssc_http_request_method(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return HTTP URL.
*/
func (obj *HttpRequest) Url() string {
    proxyResult := /*pr4*/C.vssc_http_request_url(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return HTTP body.
*/
func (obj *HttpRequest) Body() []byte {
    proxyResult := /*pr4*/C.vssc_http_request_body(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return HTTP headers.
*/
func (obj *HttpRequest) Headers() *HttpHeaderList {
    proxyResult := /*pr4*/C.vssc_http_request_headers(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewHttpHeaderListCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Setup HTTP authorization header value: "<type> <credentials>".
*
* Note, it is not added automatically to headers.
*
* Motivation: some HTTP implementations require setting authorization header explicitly,
* and forbid adding it directly to the HTTP headers (i.e. iOS NSURLRequest).
*
* See, https://developer.apple.com/documentation/foundation/nsurlrequest#1776617
*/
func (obj *HttpRequest) SetAuthHeaderValue(authHeaderValue string) {
    authHeaderValueChar := C.CString(authHeaderValue)
    defer C.free(unsafe.Pointer(authHeaderValueChar))
    authHeaderValueStr := C.vsc_str_from_str(authHeaderValueChar)

    C.vssc_http_request_set_auth_header_value(obj.cCtx, authHeaderValueStr)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(authHeaderValue)

    return
}

/*
* Setup HTTP authorization header value: "<type> <credentials>".
*
* Note, it is not added automatically to headers.
*
* Motivation: some HTTP implementations require setting authorization header explicitly,
* and forbid adding it directly to the HTTP headers (i.e. iOS NSURLRequest).
*
* See, https://developer.apple.com/documentation/foundation/nsurlrequest#1776617
*/
func (obj *HttpRequest) SetAuthHeaderValueFromTypeAndCredentials(authType string, authCredentials string) {
    authTypeChar := C.CString(authType)
    defer C.free(unsafe.Pointer(authTypeChar))
    authTypeStr := C.vsc_str_from_str(authTypeChar)
    authCredentialsChar := C.CString(authCredentials)
    defer C.free(unsafe.Pointer(authCredentialsChar))
    authCredentialsStr := C.vsc_str_from_str(authCredentialsChar)

    C.vssc_http_request_set_auth_header_value_from_type_and_credentials(obj.cCtx, authTypeStr, authCredentialsStr)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(authType)

    runtime.KeepAlive(authCredentials)

    return
}

/*
* Return HTTP authorization header value: "<type> <credentials>".
*/
func (obj *HttpRequest) AuthHeaderValue() string {
    proxyResult := /*pr4*/C.vssc_http_request_auth_header_value(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}
