package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Helps to communicate with Virgil Card Service.
*/
type CardClient struct {
    cCtx *C.vssc_card_client_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *CardClient) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewCardClient() *CardClient {
    ctx := C.vssc_card_client_new()
    obj := &CardClient {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*CardClient).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewCardClientWithCtx(pointer unsafe.Pointer) *CardClient {
    ctx := (*C.vssc_card_client_t /*ct2*/)(pointer)
    obj := &CardClient {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*CardClient).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewCardClientCopy(pointer unsafe.Pointer) *CardClient {
    ctx := (*C.vssc_card_client_t /*ct2*/)(pointer)
    obj := &CardClient {
        cCtx: C.vssc_card_client_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*CardClient).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *CardClient) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *CardClient) delete() {
    C.vssc_card_client_delete(obj.cCtx)
}

/*
* Create Card Client with a given Virgil Base URL, aka https://api.virgilsecurity.com
*/
func NewCardClientWithBaseUrl(url string) *CardClient {
    urlChar := C.CString(url)
    defer C.free(unsafe.Pointer(urlChar))
    urlStr := C.vsc_str_from_str(urlChar)

    proxyResult := /*pr4*/C.vssc_card_client_new_with_base_url(urlStr)

    runtime.KeepAlive(url)

    obj := &CardClient {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*CardClient).Delete)
    return obj
}

/*
* Create request that creates Virgil Card instance on the Virgil Cards Service.
*
* Also makes the Card accessible for search/get queries from other users.
* Note, "raw card" should contain appropriate signatures.
*/
func (obj *CardClient) MakeRequestPublishCard(rawCard *RawCard) *HttpRequest {
    proxyResult := /*pr4*/C.vssc_card_client_make_request_publish_card(obj.cCtx, (*C.vssc_raw_card_t)(unsafe.Pointer(rawCard.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(rawCard)

    return NewHttpRequestWithCtx(unsafe.Pointer(proxyResult)) /* r6 */
}

/*
* Map response to the correspond model.
* Return "raw card" of published Card.
*/
func CardClientProcessResponsePublishCard(response *HttpResponse) (*RawCard, error) {
    var error C.vssc_error_t
    C.vssc_error_reset(&error)

    proxyResult := /*pr4*/C.vssc_card_client_process_response_publish_card((*C.vssc_http_response_t)(unsafe.Pointer(response.Ctx())), &error)

    err := CoreSdkErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(response)

    return NewRawCardWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}

/*
* Create request that returns card from the Virgil Cards Service with given ID, if exists.
*/
func (obj *CardClient) MakeRequestGetCard(cardId string) *HttpRequest {
    cardIdChar := C.CString(cardId)
    defer C.free(unsafe.Pointer(cardIdChar))
    cardIdStr := C.vsc_str_from_str(cardIdChar)

    proxyResult := /*pr4*/C.vssc_card_client_make_request_get_card(obj.cCtx, cardIdStr)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(cardId)

    return NewHttpRequestWithCtx(unsafe.Pointer(proxyResult)) /* r6 */
}

/*
* Map response to the correspond model.
* Return "raw card" if Card was found.
*/
func CardClientProcessResponseGetCard(response *HttpResponse) (*RawCard, error) {
    var error C.vssc_error_t
    C.vssc_error_reset(&error)

    proxyResult := /*pr4*/C.vssc_card_client_process_response_get_card((*C.vssc_http_response_t)(unsafe.Pointer(response.Ctx())), &error)

    err := CoreSdkErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(response)

    return NewRawCardWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}

/*
* Create request that returns cards list from the Virgil Cards Service for given identity.
*/
func (obj *CardClient) MakeRequestSearchCardsWithIdentity(identity string) *HttpRequest {
    identityChar := C.CString(identity)
    defer C.free(unsafe.Pointer(identityChar))
    identityStr := C.vsc_str_from_str(identityChar)

    proxyResult := /*pr4*/C.vssc_card_client_make_request_search_cards_with_identity(obj.cCtx, identityStr)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(identity)

    return NewHttpRequestWithCtx(unsafe.Pointer(proxyResult)) /* r6 */
}

/*
* Create request that returns cards list from the Virgil Cards Service for given identities.
*
* Note, current amount of identities to search in a single request is limited to 50 items.
*/
func (obj *CardClient) MakeRequestSearchCardsWithIdentities(identities *StringList) *HttpRequest {
    proxyResult := /*pr4*/C.vssc_card_client_make_request_search_cards_with_identities(obj.cCtx, (*C.vssc_string_list_t)(unsafe.Pointer(identities.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(identities)

    return NewHttpRequestWithCtx(unsafe.Pointer(proxyResult)) /* r6 */
}

/*
* Map response to the correspond model.
* Return "raw card list" if founded Cards.
*/
func CardClientProcessResponseSearchCards(response *HttpResponse) (*RawCardList, error) {
    var error C.vssc_error_t
    C.vssc_error_reset(&error)

    proxyResult := /*pr4*/C.vssc_card_client_process_response_search_cards((*C.vssc_http_response_t)(unsafe.Pointer(response.Ctx())), &error)

    err := CoreSdkErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(response)

    return NewRawCardListWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}

/*
* Revoke an active Virgil Card using its ID only.
*
* Note, only HTTP status might be checked within a correspond response.
*/
func (obj *CardClient) MakeRequestRevokeCardWithId(cardId string) *HttpRequest {
    cardIdChar := C.CString(cardId)
    defer C.free(unsafe.Pointer(cardIdChar))
    cardIdStr := C.vsc_str_from_str(cardIdChar)

    proxyResult := /*pr4*/C.vssc_card_client_make_request_revoke_card_with_id(obj.cCtx, cardIdStr)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(cardId)

    return NewHttpRequestWithCtx(unsafe.Pointer(proxyResult)) /* r6 */
}
