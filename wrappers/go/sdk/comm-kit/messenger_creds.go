package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import foundation "virgil/foundation"
import sdk_core "virgil/sdk/core"


/*
* Contains user private key and credentials (JWT) to the messenger services.
*/
type MessengerCreds struct {
    cCtx *C.vssq_messenger_creds_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *MessengerCreds) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMessengerCreds() *MessengerCreds {
    ctx := C.vssq_messenger_creds_new()
    obj := &MessengerCreds {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MessengerCreds).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessengerCredsWithCtx(pointer unsafe.Pointer) *MessengerCreds {
    ctx := (*C.vssq_messenger_creds_t /*ct2*/)(pointer)
    obj := &MessengerCreds {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MessengerCreds).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessengerCredsCopy(pointer unsafe.Pointer) *MessengerCreds {
    ctx := (*C.vssq_messenger_creds_t /*ct2*/)(pointer)
    obj := &MessengerCreds {
        cCtx: C.vssq_messenger_creds_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*MessengerCreds).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *MessengerCreds) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *MessengerCreds) delete() {
    C.vssq_messenger_creds_delete(obj.cCtx)
}

/*
* Create fully defined object.
*/
func NewMessengerCredsWith(cardId string, username string, privateKey foundation.PrivateKey) *MessengerCreds {
    cardIdChar := C.CString(cardId)
    defer C.free(unsafe.Pointer(cardIdChar))
    cardIdStr := C.vsc_str_from_str(cardIdChar)
    usernameChar := C.CString(username)
    defer C.free(unsafe.Pointer(usernameChar))
    usernameStr := C.vsc_str_from_str(usernameChar)

    proxyResult := /*pr4*/C.vssq_messenger_creds_new_with(cardIdStr, usernameStr, (*C.vscf_impl_t)(unsafe.Pointer(privateKey.Ctx())))

    runtime.KeepAlive(cardId)

    runtime.KeepAlive(username)

    runtime.KeepAlive(privateKey)

    obj := &MessengerCreds {
        cCtx: proxyResult,
    }
    runtime.SetFinalizer(obj, (*MessengerCreds).Delete)
    return obj
}

/*
* Return identifier of the user Virgil Card.
*/
func (obj *MessengerCreds) CardId() string {
    proxyResult := /*pr4*/C.vssq_messenger_creds_card_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return the username.
*/
func (obj *MessengerCreds) Username() string {
    proxyResult := /*pr4*/C.vssq_messenger_creds_username(obj.cCtx)

    runtime.KeepAlive(obj)

    return C.GoString(C.vsc_str_chars(proxyResult)) /* r5.1 */
}

/*
* Return the user private key.
*/
func (obj *MessengerCreds) PrivateKey() (foundation.PrivateKey, error) {
    proxyResult := /*pr4*/C.vssq_messenger_creds_private_key(obj.cCtx)

    runtime.KeepAlive(obj)

    return foundation.ImplementationWrapPrivateKeyCopy(unsafe.Pointer(proxyResult)) /* r4.1 */
}

/*
* Return credentials as JSON object.
*/
func (obj *MessengerCreds) ToJson() (*sdk_core.JsonObject, error) {
    var error C.vssq_error_t
    C.vssq_error_reset(&error)

    proxyResult := /*pr4*/C.vssq_messenger_creds_to_json(obj.cCtx, &error)

    err := CommKitErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return sdk_core.NewJsonObjectWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}

/*
* Parse credentials from JSON.
*/
func MessengerCredsFromJson(jsonObj *sdk_core.JsonObject) (*MessengerCreds, error) {
    var error C.vssq_error_t
    C.vssq_error_reset(&error)

    proxyResult := /*pr4*/C.vssq_messenger_creds_from_json((*C.vssc_json_object_t)(unsafe.Pointer(jsonObj.Ctx())), &error)

    err := CommKitErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(jsonObj)

    return NewMessengerCredsWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}

/*
* Parse credentials from JSON string.
*/
func MessengerCredsFromJsonStr(jsonStr string) (*MessengerCreds, error) {
    var error C.vssq_error_t
    C.vssq_error_reset(&error)
    jsonStrChar := C.CString(jsonStr)
    defer C.free(unsafe.Pointer(jsonStrChar))
    jsonStrStr := C.vsc_str_from_str(jsonStrChar)

    proxyResult := /*pr4*/C.vssq_messenger_creds_from_json_str(jsonStrStr, &error)

    err := CommKitErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(jsonStr)

    return NewMessengerCredsWithCtx(unsafe.Pointer(proxyResult)) /* r6 */, nil
}
