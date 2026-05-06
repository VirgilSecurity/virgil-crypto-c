package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Add and/or remove recipients and it's parameters within message info.
*
* Usage:
* 1. Unpack binary message info that was obtained from RecipientCipher.
* 2. Add and/or remove key recipients.
* 3. Pack MessagInfo to the binary data.
*/
type MessageInfoEditor struct {
    cCtx *C.vscf_message_info_editor_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *MessageInfoEditor) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMessageInfoEditor() *MessageInfoEditor {
    ctx := C.vscf_message_info_editor_new()
    obj := &MessageInfoEditor {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MessageInfoEditor).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newMessageInfoEditorWithCtx(ctx *C.vscf_message_info_editor_t /*ct2*/) *MessageInfoEditor {
    obj := &MessageInfoEditor {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MessageInfoEditor).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newMessageInfoEditorCopy(ctx *C.vscf_message_info_editor_t /*ct2*/) *MessageInfoEditor {
    obj := &MessageInfoEditor {
        cCtx: C.vscf_message_info_editor_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*MessageInfoEditor).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *MessageInfoEditor) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *MessageInfoEditor) delete() {
    C.vscf_message_info_editor_delete(obj.cCtx)
}

func (obj *MessageInfoEditor) SetRandom(random Random) {
    C.vscf_message_info_editor_release_random(obj.cCtx)
    C.vscf_message_info_editor_use_random(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(random.Ctx())))

    runtime.KeepAlive(random)
    runtime.KeepAlive(obj)
}

/*
* Set dependencies to it's defaults.
*/
func (obj *MessageInfoEditor) SetupDefaults() error {
    proxyResult := /*pr4*/C.vscf_message_info_editor_setup_defaults(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Unpack serialized message info.
*
* Note that recipients can only be removed but not added.
* Note, use "unlock" method to be able to add new recipients as well.
*/
func (obj *MessageInfoEditor) Unpack(messageInfoData []byte) error {
    messageInfoDataData := helperWrapData (messageInfoData)

    proxyResult := /*pr4*/C.vscf_message_info_editor_unpack(obj.cCtx, messageInfoDataData)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Decrypt encryption key this allows adding new recipients.
*/
func (obj *MessageInfoEditor) Unlock(ownerRecipientId []byte, ownerPrivateKey PrivateKey) error {
    ownerRecipientIdData := helperWrapData (ownerRecipientId)

    proxyResult := /*pr4*/C.vscf_message_info_editor_unlock(obj.cCtx, ownerRecipientIdData, (*C.vscf_impl_t)(unsafe.Pointer(ownerPrivateKey.Ctx())))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(ownerPrivateKey)

    return nil
}

/*
* Add recipient defined with id and public key.
*/
func (obj *MessageInfoEditor) AddKeyRecipient(recipientId []byte, publicKey PublicKey) error {
    recipientIdData := helperWrapData (recipientId)

    proxyResult := /*pr4*/C.vscf_message_info_editor_add_key_recipient(obj.cCtx, recipientIdData, (*C.vscf_impl_t)(unsafe.Pointer(publicKey.Ctx())))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    runtime.KeepAlive(publicKey)

    return nil
}

/*
* Remove recipient with a given id.
* Return false if recipient with given id was not found.
*/
func (obj *MessageInfoEditor) RemoveKeyRecipient(recipientId []byte) bool {
    recipientIdData := helperWrapData (recipientId)

    proxyResult := /*pr4*/C.vscf_message_info_editor_remove_key_recipient(obj.cCtx, recipientIdData)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Remove all existent recipients.
*/
func (obj *MessageInfoEditor) RemoveAll() {
    C.vscf_message_info_editor_remove_all(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Return length of serialized message info.
* Actual length can be obtained right after applying changes.
*/
func (obj *MessageInfoEditor) PackedLen() uint {
    proxyResult := /*pr4*/C.vscf_message_info_editor_packed_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Return serialized message info.
* Precondition: this method can be called after "apply".
*/
func (obj *MessageInfoEditor) Pack() []byte {
    messageInfoBuf, messageInfoBufErr := newBuffer(int(obj.PackedLen() /* lg2 */))
    if messageInfoBufErr != nil {
        return nil
    }
    defer messageInfoBuf.delete()


    C.vscf_message_info_editor_pack(obj.cCtx, messageInfoBuf.ctx)

    runtime.KeepAlive(obj)

    return messageInfoBuf.getData() /* r7 */
}
