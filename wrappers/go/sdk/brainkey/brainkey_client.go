package sdk_brainkey

// #include <virgil/sdk/brainkey/vssb_brainkey_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import sdk_core "virgil/sdk/core"


/*
* Helps to communicate with Virgil Brainkey Service.
*/
type BrainkeyClient struct {
    cCtx *C.vssb_brainkey_client_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *BrainkeyClient) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewBrainkeyClient() *BrainkeyClient {
    ctx := C.vssb_brainkey_client_new()
    obj := &BrainkeyClient {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*BrainkeyClient).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewBrainkeyClientWithCtx(pointer unsafe.Pointer) *BrainkeyClient {
    ctx := (*C.vssb_brainkey_client_t /*ct2*/)(pointer)
    obj := &BrainkeyClient {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*BrainkeyClient).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewBrainkeyClientCopy(pointer unsafe.Pointer) *BrainkeyClient {
    ctx := (*C.vssb_brainkey_client_t /*ct2*/)(pointer)
    obj := &BrainkeyClient {
        cCtx: C.vssb_brainkey_client_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*BrainkeyClient).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *BrainkeyClient) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *BrainkeyClient) delete() {
    C.vssb_brainkey_client_delete(obj.cCtx)
}

/*
* Create Brainkey Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
*/
func NewBrainkeyClientWithBaseUrl(url string) *BrainkeyClient {
    urlChar := C.CString(url)
    defer C.free(unsafe.Pointer(urlChar))
    urlStr := C.vsc_str_from_str(urlChar)

    proxyResult := /*pr4*/C.vssb_brainkey_client_new_with_base_url(urlStr)

    runtime.KeepAlive(url)

    obj := &BrainkeyClient {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*BrainkeyClient).Delete)
    return obj
}

/*
* Create request that makes a hardened point from a blinded point.
*/
func (obj *BrainkeyClient) MakeRequestHardenPoint(blindedPoint []byte) *sdk_core.HttpRequest {
    blindedPointData := helperWrapData (blindedPoint)

    proxyResult := /*pr4*/C.vssb_brainkey_client_make_request_harden_point(obj.cCtx, blindedPointData)

    runtime.KeepAlive(obj)

    return sdk_core.NewHttpRequestWithCtx(unsafe.Pointer(proxyResult)) /* r6 */
}

/*
* Map response to the correspond model.
*/
func BrainkeyClientProcessResponseHardenPoint(response *sdk_core.HttpResponse) (*BrainkeyHardenedPoint, error) {
    var error C.vssb_error_t
    C.vssb_error_reset(&error)

    proxyResult := /*pr4*/C.vssb_brainkey_client_process_response_harden_point((*C.vssc_http_response_t)(unsafe.Pointer(response.Ctx())), &error)

    err := BrainkeySdkErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(response)

    return NewBrainkeyHardenedPointWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}
