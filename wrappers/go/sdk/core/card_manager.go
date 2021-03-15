package sdk_core

// #include <virgil/sdk/core/vssc_core_sdk_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import foundation "virgil/foundation"


/*
* Class responsible for operations with Virgil Cards and it's representations.
*/
type CardManager struct {
    cCtx *C.vssc_card_manager_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *CardManager) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewCardManager() *CardManager {
    ctx := C.vssc_card_manager_new()
    obj := &CardManager {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*CardManager).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newCardManagerWithCtx(ctx *C.vssc_card_manager_t /*ct2*/) *CardManager {
    obj := &CardManager {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*CardManager).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newCardManagerCopy(ctx *C.vssc_card_manager_t /*ct2*/) *CardManager {
    obj := &CardManager {
        cCtx: C.vssc_card_manager_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*CardManager).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *CardManager) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *CardManager) delete() {
    C.vssc_card_manager_delete(obj.cCtx)
}

func (obj *CardManager) SetRandom(random foundation.Random) {
    C.vssc_card_manager_release_random(obj.cCtx)
    C.vssc_card_manager_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

/*
* Configure internal states and dependencies.
*/
func (obj *CardManager) Configure() error {
    proxyResult := /*pr4*/C.vssc_card_manager_configure(obj.cCtx)

    err := CoreSdkErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Configure internal states and dependencies.
* Virgil Service Public Key can be customized (i.e. for stage env).
*/
func (obj *CardManager) ConfigureWithServicePublicKey(publicKeyData []byte) error {
    publicKeyDataData := helperWrapData (publicKeyData)

    proxyResult := /*pr4*/C.vssc_card_manager_configure_with_service_public_key(obj.cCtx, publicKeyDataData)

    err := CoreSdkErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Generates self-signed "raw card".
*/
func (obj *CardManager) GenerateRawCard(identity string, privateKey foundation.PrivateKey) (*RawCard, error) {
    var error C.vssc_error_t
    C.vssc_error_reset(&error)
    identityChar := C.CString(identity)
    defer C.free(unsafe.Pointer(identityChar))
    identityStr := C.vsc_str_from_str(identityChar)

    proxyResult := /*pr4*/C.vssc_card_manager_generate_raw_card(obj.cCtx, identityStr, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), &error)

    err := CoreSdkErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(identity)

    runtime.KeepAlive(privateKey)

    return newRawCardWithCtx(proxyResult) /* r6 */, nil
}

/*
* Generates self-signed "raw card" with a defined previous card id.
*/
func (obj *CardManager) GenerateReplacementRawCard(identity string, privateKey foundation.PrivateKey, previousCardId string) (*RawCard, error) {
    var error C.vssc_error_t
    C.vssc_error_reset(&error)
    identityChar := C.CString(identity)
    defer C.free(unsafe.Pointer(identityChar))
    identityStr := C.vsc_str_from_str(identityChar)
    previousCardIdChar := C.CString(previousCardId)
    defer C.free(unsafe.Pointer(previousCardIdChar))
    previousCardIdStr := C.vsc_str_from_str(previousCardIdChar)

    proxyResult := /*pr4*/C.vssc_card_manager_generate_replacement_raw_card(obj.cCtx, identityStr, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())), previousCardIdStr, &error)

    err := CoreSdkErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(identity)

    runtime.KeepAlive(privateKey)

    runtime.KeepAlive(previousCardId)

    return newRawCardWithCtx(proxyResult) /* r6 */, nil
}

/*
* Create Card from "raw card" and verify it.
*
* Note, only self signature and Virgil Cards Service signatures are verified.
*/
func (obj *CardManager) ImportRawCard(rawCard *RawCard) (*Card, error) {
    var error C.vssc_error_t
    C.vssc_error_reset(&error)

    proxyResult := /*pr4*/C.vssc_card_manager_import_raw_card(obj.cCtx, (*C.vssc_raw_card_t)(unsafe.Pointer(rawCard.Ctx())), &error)

    err := CoreSdkErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(rawCard)

    return newCardWithCtx(proxyResult) /* r6 */, nil
}

/*
* Create list of Cards from "raw card list" and verify it.
*
* Note, only self signature and Virgil Cards Service signatures are verified.
*/
func (obj *CardManager) ImportRawCardList(rawCardList *RawCardList) (*CardList, error) {
    var error C.vssc_error_t
    C.vssc_error_reset(&error)

    proxyResult := /*pr4*/C.vssc_card_manager_import_raw_card_list(obj.cCtx, (*C.vssc_raw_card_list_t)(unsafe.Pointer(rawCardList.Ctx())), &error)

    err := CoreSdkErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(rawCardList)

    return newCardListWithCtx(proxyResult) /* r6 */, nil
}

/*
* Create Card with expected card identifier from "raw card" and verify it.
*
* Note, only self signature and Virgil Cards Service signatures are verified.
*/
func (obj *CardManager) ImportRawCardWithId(rawCard *RawCard, cardId string) (*Card, error) {
    var error C.vssc_error_t
    C.vssc_error_reset(&error)
    cardIdChar := C.CString(cardId)
    defer C.free(unsafe.Pointer(cardIdChar))
    cardIdStr := C.vsc_str_from_str(cardIdChar)

    proxyResult := /*pr4*/C.vssc_card_manager_import_raw_card_with_id(obj.cCtx, (*C.vssc_raw_card_t)(unsafe.Pointer(rawCard.Ctx())), cardIdStr, &error)

    err := CoreSdkErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(rawCard)

    runtime.KeepAlive(cardId)

    return newCardWithCtx(proxyResult) /* r6 */, nil
}

/*
* Create Card from "raw card" with additional check which ensures
* that Virgil Cards Service do not change self-signature.
*
* Note, only self signature and Virgil Cards Service signatures are verified.
*/
func (obj *CardManager) ImportRawCardWithInitialRawCard(rawCard *RawCard, initialRawCard *RawCard) (*Card, error) {
    var error C.vssc_error_t
    C.vssc_error_reset(&error)

    proxyResult := /*pr4*/C.vssc_card_manager_import_raw_card_with_initial_raw_card(obj.cCtx, (*C.vssc_raw_card_t)(unsafe.Pointer(rawCard.Ctx())), (*C.vssc_raw_card_t)(unsafe.Pointer(initialRawCard.Ctx())), &error)

    err := CoreSdkErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(rawCard)

    runtime.KeepAlive(initialRawCard)

    return newCardWithCtx(proxyResult) /* r6 */, nil
}
