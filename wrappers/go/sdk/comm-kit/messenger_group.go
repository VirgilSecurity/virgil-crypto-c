package sdk_comm_kit

// #include <virgil/sdk/comm-kit/vssq_comm_kit_public.h>
import "C"
import unsafe "unsafe"
import "runtime"
import foundation "virgil/foundation"
import sdk_core "virgil/sdk/core"


/*
* Contains information about the group and performs encryption and decryption operations.
*/
type MessengerGroup struct {
    cCtx *C.vssq_messenger_group_t /*ct2*/
}
const (
    MessengerGroupSessionIdLen uint = 32
)

/* Handle underlying C context. */
func (obj *MessengerGroup) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMessengerGroup() *MessengerGroup {
    ctx := C.vssq_messenger_group_new()
    obj := &MessengerGroup {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MessengerGroup).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessengerGroupWithCtx(pointer unsafe.Pointer) *MessengerGroup {
    ctx := (*C.vssq_messenger_group_t /*ct2*/)(pointer)
    obj := &MessengerGroup {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MessengerGroup).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessengerGroupCopy(pointer unsafe.Pointer) *MessengerGroup {
    ctx := (*C.vssq_messenger_group_t /*ct2*/)(pointer)
    obj := &MessengerGroup {
        cCtx: C.vssq_messenger_group_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*MessengerGroup).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *MessengerGroup) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *MessengerGroup) delete() {
    C.vssq_messenger_group_delete(obj.cCtx)
}

func (obj *MessengerGroup) SetRandom(random foundation.Random) {
    C.vssq_messenger_group_release_random(obj.cCtx)
    C.vssq_messenger_group_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

func (obj *MessengerGroup) SetAuth(auth *MessengerAuth) {
    C.vssq_messenger_group_release_auth(obj.cCtx)
    C.vssq_messenger_group_use_auth(obj.cCtx, (*C.vssq_messenger_auth_t)(unsafe.Pointer(auth.Ctx())))

    runtime.KeepAlive(auth)
    runtime.KeepAlive(obj)
}

/*
* Return user info of the group owner.
*/
func (obj *MessengerGroup) Owner() *MessengerUser {
    proxyResult := /*pr4*/C.vssq_messenger_group_owner(obj.cCtx)

    runtime.KeepAlive(obj)

    return NewMessengerUserCopy(unsafe.Pointer(proxyResult)) /* r5 */
}

/*
* Return the group as JSON object.
*
* JSON format:
* {
* "version" : "v1",
* "group_id" : "STRING",
* "owner" : {},
* "epochs" : []
* }
*/
func (obj *MessengerGroup) ToJson() *sdk_core.JsonObject {
    proxyResult := /*pr4*/C.vssq_messenger_group_to_json(obj.cCtx)

    runtime.KeepAlive(obj)

    return sdk_core.NewJsonObjectWithCtx(unsafe.Pointer(proxyResult)) /* r6 */
}

/*
* Delete group.
*/
func (obj *MessengerGroup) Remove() error {
    proxyResult := /*pr4*/C.vssq_messenger_group_remove(obj.cCtx)

    err := CommKitErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Return a buffer length enough to hold an encrypted message.
*/
func (obj *MessengerGroup) EncryptedMessageLen(plaintextLen uint) uint {
    proxyResult := /*pr4*/C.vssq_messenger_group_encrypted_message_len(obj.cCtx, (C.size_t)(plaintextLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Encrypt a group message.
*/
func (obj *MessengerGroup) EncryptMessage(plaintext string) ([]byte, error) {
    plaintextChar := C.CString(plaintext)
    defer C.free(unsafe.Pointer(plaintextChar))
    plaintextStr := C.vsc_str_from_str(plaintextChar)

    outBuf, outBufErr := newBuffer(int(obj.EncryptedMessageLen(uint(len(plaintext))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()


    proxyResult := /*pr4*/C.vssq_messenger_group_encrypt_message(obj.cCtx, plaintextStr, outBuf.ctx)

    err := CommKitErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(plaintext)

    return outBuf.getData() /* r7 */, nil
}

/*
* Encrypt a group message.
*/
func (obj *MessengerGroup) EncryptBinaryMessage(data []byte) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.EncryptedMessageLen(uint(len(data))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vssq_messenger_group_encrypt_binary_message(obj.cCtx, dataData, outBuf.ctx)

    err := CommKitErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return outBuf.getData() /* r7 */, nil
}

/*
* Return a buffer length enough to hold a decrypted message.
*/
func (obj *MessengerGroup) DecryptedMessageLen(encryptedLen uint) uint {
    proxyResult := /*pr4*/C.vssq_messenger_group_decrypted_message_len(obj.cCtx, (C.size_t)(encryptedLen)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Decrypt a group message.
*/
func (obj *MessengerGroup) DecryptMessage(encryptedMessage []byte, fromUser *MessengerUser) (string, error) {
    outBuf := C.vsc_str_buffer_new_with_capacity((C.size_t)(obj.DecryptedMessageLen(uint(len(encryptedMessage))) /* lg2 */))
    defer C.vsc_str_buffer_delete(outBuf)
    encryptedMessageData := helperWrapData (encryptedMessage)

    proxyResult := /*pr4*/C.vssq_messenger_group_decrypt_message(obj.cCtx, encryptedMessageData, (*C.vssq_messenger_user_t)(unsafe.Pointer(fromUser.Ctx())), outBuf)

    err := CommKitErrorHandleStatus(proxyResult)
    if err != nil {
        return "", err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(fromUser)

    return C.GoString(C.vsc_str_buffer_chars(outBuf)) /* r7.1 */, nil
}

/*
* Decrypt a group message.
*/
func (obj *MessengerGroup) DecryptBinaryMessage(encryptedMessage []byte, fromUser *MessengerUser) ([]byte, error) {
    outBuf, outBufErr := newBuffer(int(obj.DecryptedMessageLen(uint(len(encryptedMessage))) /* lg2 */))
    if outBufErr != nil {
        return nil, outBufErr
    }
    defer outBuf.delete()
    encryptedMessageData := helperWrapData (encryptedMessage)

    proxyResult := /*pr4*/C.vssq_messenger_group_decrypt_binary_message(obj.cCtx, encryptedMessageData, (*C.vssq_messenger_user_t)(unsafe.Pointer(fromUser.Ctx())), outBuf.ctx)

    err := CommKitErrorHandleStatus(proxyResult)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(fromUser)

    return outBuf.getData() /* r7 */, nil
}

/*
* Check if current user can modify a group.
*/
func (obj *MessengerGroup) CheckPermissionModify() bool {
    proxyResult := /*pr4*/C.vssq_messenger_group_check_permission_modify(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}
