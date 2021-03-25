package sdk_keyknox

// #include <virgil/sdk/keyknox/vssk_keyknox_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import sdk_core "virgil/sdk/core"


/*
* Helps to communicate with Virgil Keyknox Service.
*/
type KeyknoxClient struct {
    cCtx *C.vssk_keyknox_client_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *KeyknoxClient) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewKeyknoxClient() *KeyknoxClient {
    ctx := C.vssk_keyknox_client_new()
    obj := &KeyknoxClient {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*KeyknoxClient).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewKeyknoxClientWithCtx(pointer unsafe.Pointer) *KeyknoxClient {
    ctx := (*C.vssk_keyknox_client_t /*ct2*/)(pointer)
    obj := &KeyknoxClient {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*KeyknoxClient).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewKeyknoxClientCopy(pointer unsafe.Pointer) *KeyknoxClient {
    ctx := (*C.vssk_keyknox_client_t /*ct2*/)(pointer)
    obj := &KeyknoxClient {
        cCtx: C.vssk_keyknox_client_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*KeyknoxClient).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *KeyknoxClient) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *KeyknoxClient) delete() {
    C.vssk_keyknox_client_delete(obj.cCtx)
}

/*
* Create Keyknox Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
*/
func NewKeyknoxClientWithBaseUrl(url string) *KeyknoxClient {
    urlChar := C.CString(url)
    defer C.free(unsafe.Pointer(urlChar))
    urlStr := C.vsc_str_from_str(urlChar)

    proxyResult := /*pr4*/C.vssk_keyknox_client_new_with_base_url(urlStr)

    runtime.KeepAlive(url)

    obj := &KeyknoxClient {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*KeyknoxClient).Delete)
    return obj
}

/*
* Create request that performs push operation.
*/
func (obj *KeyknoxClient) MakeRequestPush(newEntry *KeyknoxEntry) *sdk_core.HttpRequest {
    proxyResult := /*pr4*/C.vssk_keyknox_client_make_request_push(obj.cCtx, (*C.vssk_keyknox_entry_t)(unsafe.Pointer(newEntry.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(newEntry)

    return sdk_core.NewHttpRequestWithCtx(unsafe.Pointer(proxyResult)) /* r6 */
}

/*
* Map response to the correspond model.
*/
func KeyknoxClientProcessResponsePush(response *sdk_core.HttpResponse) (*KeyknoxEntry, error) {
    var error C.vssk_error_t
    C.vssk_error_reset(&error)

    proxyResult := /*pr4*/C.vssk_keyknox_client_process_response_push((*C.vssc_http_response_t)(unsafe.Pointer(response.Ctx())), &error)

    err := KeyknoxSdkErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(response)

    return NewKeyknoxEntryWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}

/*
* Create request that performs pull operation.
* Note, identity can be empty.
*/
func (obj *KeyknoxClient) MakeRequestPull(root string, path string, key string, identity string) *sdk_core.HttpRequest {
    rootChar := C.CString(root)
    defer C.free(unsafe.Pointer(rootChar))
    rootStr := C.vsc_str_from_str(rootChar)
    pathChar := C.CString(path)
    defer C.free(unsafe.Pointer(pathChar))
    pathStr := C.vsc_str_from_str(pathChar)
    keyChar := C.CString(key)
    defer C.free(unsafe.Pointer(keyChar))
    keyStr := C.vsc_str_from_str(keyChar)
    identityChar := C.CString(identity)
    defer C.free(unsafe.Pointer(identityChar))
    identityStr := C.vsc_str_from_str(identityChar)

    proxyResult := /*pr4*/C.vssk_keyknox_client_make_request_pull(obj.cCtx, rootStr, pathStr, keyStr, identityStr)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(root)

    runtime.KeepAlive(path)

    runtime.KeepAlive(key)

    runtime.KeepAlive(identity)

    return sdk_core.NewHttpRequestWithCtx(unsafe.Pointer(proxyResult)) /* r6 */
}

/*
* Map response to the correspond model.
*/
func KeyknoxClientProcessResponsePull(response *sdk_core.HttpResponse) (*KeyknoxEntry, error) {
    var error C.vssk_error_t
    C.vssk_error_reset(&error)

    proxyResult := /*pr4*/C.vssk_keyknox_client_process_response_pull((*C.vssc_http_response_t)(unsafe.Pointer(response.Ctx())), &error)

    err := KeyknoxSdkErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(response)

    return NewKeyknoxEntryWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}

/*
* Create request that performs reset operation.
*
* Note, all parameters can be empty.
* Note, if identity is given, only "key" parameter can be optional.
*/
func (obj *KeyknoxClient) MakeRequestReset(root string, path string, key string, identity string) *sdk_core.HttpRequest {
    rootChar := C.CString(root)
    defer C.free(unsafe.Pointer(rootChar))
    rootStr := C.vsc_str_from_str(rootChar)
    pathChar := C.CString(path)
    defer C.free(unsafe.Pointer(pathChar))
    pathStr := C.vsc_str_from_str(pathChar)
    keyChar := C.CString(key)
    defer C.free(unsafe.Pointer(keyChar))
    keyStr := C.vsc_str_from_str(keyChar)
    identityChar := C.CString(identity)
    defer C.free(unsafe.Pointer(identityChar))
    identityStr := C.vsc_str_from_str(identityChar)

    proxyResult := /*pr4*/C.vssk_keyknox_client_make_request_reset(obj.cCtx, rootStr, pathStr, keyStr, identityStr)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(root)

    runtime.KeepAlive(path)

    runtime.KeepAlive(key)

    runtime.KeepAlive(identity)

    return sdk_core.NewHttpRequestWithCtx(unsafe.Pointer(proxyResult)) /* r6 */
}

/*
* Map response to the correspond model.
*/
func KeyknoxClientProcessResponseReset(response *sdk_core.HttpResponse) (*KeyknoxEntry, error) {
    var error C.vssk_error_t
    C.vssk_error_reset(&error)

    proxyResult := /*pr4*/C.vssk_keyknox_client_process_response_reset((*C.vssc_http_response_t)(unsafe.Pointer(response.Ctx())), &error)

    err := KeyknoxSdkErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(response)

    return NewKeyknoxEntryWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}

/*
* Create request that performs get keys operation.
*
* Note, all parameters can be empty.
*/
func (obj *KeyknoxClient) MakeRequestGetKeys(root string, path string, identity string) *sdk_core.HttpRequest {
    rootChar := C.CString(root)
    defer C.free(unsafe.Pointer(rootChar))
    rootStr := C.vsc_str_from_str(rootChar)
    pathChar := C.CString(path)
    defer C.free(unsafe.Pointer(pathChar))
    pathStr := C.vsc_str_from_str(pathChar)
    identityChar := C.CString(identity)
    defer C.free(unsafe.Pointer(identityChar))
    identityStr := C.vsc_str_from_str(identityChar)

    proxyResult := /*pr4*/C.vssk_keyknox_client_make_request_get_keys(obj.cCtx, rootStr, pathStr, identityStr)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(root)

    runtime.KeepAlive(path)

    runtime.KeepAlive(identity)

    return sdk_core.NewHttpRequestWithCtx(unsafe.Pointer(proxyResult)) /* r6 */
}

/*
* Map response to the correspond model.
*/
func KeyknoxClientProcessResponseGetKeys(response *sdk_core.HttpResponse) (*sdk_core.StringList, error) {
    var error C.vssk_error_t
    C.vssk_error_reset(&error)

    proxyResult := /*pr4*/C.vssk_keyknox_client_process_response_get_keys((*C.vssc_http_response_t)(unsafe.Pointer(response.Ctx())), &error)

    err := KeyknoxSdkErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(response)

    return sdk_core.NewStringListWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}
