package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* This class contains HTTP response information alongside with information
* that is specific for the Virgil services.
*/
type HttpResponse struct {
    cCtx *C.vssc_http_response_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *HttpResponse) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewHttpResponse() *HttpResponse {
    ctx := C.vssc_http_response_new()
    obj := &HttpResponse {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*HttpResponse).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewHttpResponseWithCtx(pointer unsafe.Pointer) *HttpResponse {
    ctx := (*C.vssc_http_response_t /*ct2*/)(pointer)
    obj := &HttpResponse {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*HttpResponse).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewHttpResponseCopy(pointer unsafe.Pointer) *HttpResponse {
    ctx := (*C.vssc_http_response_t /*ct2*/)(pointer)
    obj := &HttpResponse {
        cCtx: C.vssc_http_response_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*HttpResponse).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *HttpResponse) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *HttpResponse) delete() {
    C.vssc_http_response_delete(obj.cCtx)
}

/*
* Create response with a status only.
*/
func NewHttpResponseWithStatus(statusCode uint) *HttpResponse {
    proxyResult := /*pr4*/C.vssc_http_response_new_with_status((C.size_t)(statusCode)/*pa10*/)

    obj := &HttpResponse {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*HttpResponse).Delete)
    return obj
}

/*
* Create response with a status and body.
*/
func NewHttpResponseWithBody(statusCode uint, body []byte) *HttpResponse {
    bodyData := helperWrapData (body)

    proxyResult := /*pr4*/C.vssc_http_response_new_with_body((C.size_t)(statusCode)/*pa10*/, bodyData)

    obj := &HttpResponse {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*HttpResponse).Delete)
    return obj
}

/*
* Set HTTP status.
*/
func (obj *HttpResponse) SetStatus(statusCode uint) {
    C.vssc_http_response_set_status(obj.cCtx, (C.size_t)(statusCode)/*pa10*/)

    runtime.KeepAlive(obj)

    return
}

/*
* Set HTTP body.
*/
func (obj *HttpResponse) SetBody(body []byte) {
    bodyData := helperWrapData (body)

    C.vssc_http_response_set_body(obj.cCtx, bodyData)

    runtime.KeepAlive(obj)

    return
}

/*
* Add HTTP header.
*/
func (obj *HttpResponse) AddHeader(name string, value string) {
    nameChar := C.CString(name)
    defer C.free(unsafe.Pointer(nameChar))
    nameStr := C.vsc_str_from_str(nameChar)
    valueChar := C.CString(value)
    defer C.free(unsafe.Pointer(valueChar))
    valueStr := C.vsc_str_from_str(valueChar)

    C.vssc_http_response_add_header(obj.cCtx, nameStr, valueStr)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(name)

    runtime.KeepAlive(value)

    return
}

/*
* Return true if underlying status code is in range [200..299].
*/
func (obj *HttpResponse) IsSuccess() bool {
    proxyResult := /*pr4*/C.vssc_http_response_is_success(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return HTTP status code.
*/
func (obj *HttpResponse) StatusCode() uint {
    proxyResult := /*pr4*/C.vssc_http_response_status_code(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Return HTTP body.
*/
func (obj *HttpResponse) Body() []byte {
    proxyResult := /*pr4*/C.vssc_http_response_body(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return HTTP headers.
*/
func (obj *HttpResponse) Headers() *HttpHeaderList {
    proxyResult := /*pr4*/C.vssc_http_response_headers(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewHttpHeaderListCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Find header by it's name.
*/
func (obj *HttpResponse) FindHeader(name string) (string, error) {
    var error C.vssc_error_t
    C.vssc_error_reset(&error)
    nameChar := C.CString(name)
    defer C.free(unsafe.Pointer(nameChar))
    nameStr := C.vsc_str_from_str(nameChar)

    proxyResult := /*pr4*/C.vssc_http_response_find_header(obj.cCtx, nameStr, &error)

    err := CoreSdkErrorHandleStatus(error.status)
    if err != nil {
        return "", err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(name)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */, nil
}

/*
* Return true if response handles a valid body as JSON object.
*/
func (obj *HttpResponse) BodyIsJsonObject() bool {
    proxyResult := /*pr4*/C.vssc_http_response_body_is_json_object(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return true if response handles a valid body as JSON array.
*/
func (obj *HttpResponse) BodyIsJsonArray() bool {
    proxyResult := /*pr4*/C.vssc_http_response_body_is_json_array(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return response body as JSON object.
*/
func (obj *HttpResponse) BodyAsJsonObject() *JsonObject {
    proxyResult := /*pr4*/C.vssc_http_response_body_as_json_object(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewJsonObjectCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return response body as JSON array.
*/
func (obj *HttpResponse) BodyAsJsonArray() *JsonArray {
    proxyResult := /*pr4*/C.vssc_http_response_body_as_json_array(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewJsonArrayCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return true if response handles a service error and it's description.
*/
func (obj *HttpResponse) HasServiceError() bool {
    proxyResult := /*pr4*/C.vssc_http_response_has_service_error(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return service error code.
*/
func (obj *HttpResponse) ServiceErrorCode() uint {
    proxyResult := /*pr4*/C.vssc_http_response_service_error_code(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Return service error description.
* Note, empty string can be returned.
*/
func (obj *HttpResponse) ServiceErrorDescription() string {
    proxyResult := /*pr4*/C.vssc_http_response_service_error_description(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Check status code range [200..299].
*/
func HttpResponseIsStatusCodeSuccess(httpStatusCode uint) bool {
    proxyResult := /*pr4*/C.vssc_http_response_is_status_code_success((C.size_t)(httpStatusCode)/*pa10*/)

    return bool(proxyResult) /* r9 */
}
