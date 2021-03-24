package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import "runtime"
import unsafe "unsafe"

/*
* Virgil HTTP client.
* TODO: Add "virgil-agent" header.
 */
type VirgilHttpClient struct {
}

const (
	/*
	 * Authorization type: Virgil
	 */
	VirgilHttpClientKAuthTypeVirgil string = "Virgil"
)

/*
* Send request over HTTP.
 */
func VirgilHttpClientSend(httpRequest *HttpRequest) (*HttpResponse, error) {
	var error C.vssc_error_t
	C.vssc_error_reset(&error)

	proxyResult := /*pr4*/ C.vssc_virgil_http_client_send((*C.vssc_http_request_t)(unsafe.Pointer(httpRequest.Ctx())), &error)

	err := CoreSdkErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(httpRequest)

	return NewHttpResponseWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}

/*
* Send request over HTTP with a path to Certificate Authority bundle.
*
* Note, argument "ca bundle path" can be empty.
 */
func VirgilHttpClientSendWithCa(httpRequest *HttpRequest, caBundlePath string) (*HttpResponse, error) {
	var error C.vssc_error_t
	C.vssc_error_reset(&error)
	caBundlePathChar := C.CString(caBundlePath)
	defer C.free(unsafe.Pointer(caBundlePathChar))
	caBundlePathStr := C.vsc_str_from_str(caBundlePathChar)

	proxyResult := /*pr4*/ C.vssc_virgil_http_client_send_with_ca((*C.vssc_http_request_t)(unsafe.Pointer(httpRequest.Ctx())), caBundlePathStr, &error)

	err := CoreSdkErrorHandleStatus(error.status)
	if err != nil {
		return nil, err
	}

	runtime.KeepAlive(httpRequest)

	runtime.KeepAlive(caBundlePath)

	return NewHttpResponseWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}
