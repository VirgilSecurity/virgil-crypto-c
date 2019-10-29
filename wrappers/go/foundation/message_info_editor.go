package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

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
func (this MessageInfoEditor) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewMessageInfoEditor () *MessageInfoEditor {
    ctx := C.vscf_message_info_editor_new()
    return &MessageInfoEditor {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newMessageInfoEditorWithCtx (ctx *C.vscf_message_info_editor_t /*ct2*/) *MessageInfoEditor {
    return &MessageInfoEditor {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newMessageInfoEditorCopy (ctx *C.vscf_message_info_editor_t /*ct2*/) *MessageInfoEditor {
    return &MessageInfoEditor {
        cCtx: C.vscf_message_info_editor_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this MessageInfoEditor) close () {
    C.vscf_message_info_editor_delete(this.cCtx)
}

func (this MessageInfoEditor) SetRandom (random IRandom) {
    C.vscf_message_info_editor_release_random(this.cCtx)
    C.vscf_message_info_editor_use_random(this.cCtx, (*C.vscf_impl_t)(random.ctx()))
}

/*
* Set dependencies to it's defaults.
*/
func (this MessageInfoEditor) SetupDefaults () error {
    proxyResult := /*pr4*/C.vscf_message_info_editor_setup_defaults(this.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Unpack serialized message info.
*
* Note that recipients can only be removed but not added.
* Note, use "unlock" method to be able to add new recipients as well.
*/
func (this MessageInfoEditor) Unpack (messageInfoData []byte) error {
    messageInfoDataData := C.vsc_data((*C.uint8_t)(&messageInfoData[0]), C.size_t(len(messageInfoData)))

    proxyResult := /*pr4*/C.vscf_message_info_editor_unpack(this.cCtx, messageInfoDataData)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Decrypt encryption key this allows adding new recipients.
*/
func (this MessageInfoEditor) Unlock (ownerRecipientId []byte, ownerPrivateKey IPrivateKey) error {
    ownerRecipientIdData := C.vsc_data((*C.uint8_t)(&ownerRecipientId[0]), C.size_t(len(ownerRecipientId)))

    proxyResult := /*pr4*/C.vscf_message_info_editor_unlock(this.cCtx, ownerRecipientIdData, (*C.vscf_impl_t)(ownerPrivateKey.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Add recipient defined with id and public key.
*/
func (this MessageInfoEditor) AddKeyRecipient (recipientId []byte, publicKey IPublicKey) error {
    recipientIdData := C.vsc_data((*C.uint8_t)(&recipientId[0]), C.size_t(len(recipientId)))

    proxyResult := /*pr4*/C.vscf_message_info_editor_add_key_recipient(this.cCtx, recipientIdData, (*C.vscf_impl_t)(publicKey.ctx()))

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Remove recipient with a given id.
* Return false if recipient with given id was not found.
*/
func (this MessageInfoEditor) RemoveKeyRecipient (recipientId []byte) bool {
    recipientIdData := C.vsc_data((*C.uint8_t)(&recipientId[0]), C.size_t(len(recipientId)))

    proxyResult := /*pr4*/C.vscf_message_info_editor_remove_key_recipient(this.cCtx, recipientIdData)

    return bool(proxyResult) /* r9 */
}

/*
* Remove all existent recipients.
*/
func (this MessageInfoEditor) RemoveAll () {
    C.vscf_message_info_editor_remove_all(this.cCtx)

    return
}

/*
* Return length of serialized message info.
* Actual length can be obtained right after applying changes.
*/
func (this MessageInfoEditor) PackedLen () uint32 {
    proxyResult := /*pr4*/C.vscf_message_info_editor_packed_len(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Return serialized message info.
* Precondition: this method can be called after "apply".
*/
func (this MessageInfoEditor) Pack () []byte {
    messageInfoCount := C.ulong(this.PackedLen() /* lg2 */)
    messageInfoMemory := make([]byte, int(C.vsc_buffer_ctx_size() + messageInfoCount))
    messageInfoBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&messageInfoMemory[0]))
    messageInfoData := messageInfoMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(messageInfoBuf)
    C.vsc_buffer_use(messageInfoBuf, (*C.byte)(unsafe.Pointer(&messageInfoData[0])), messageInfoCount)
    defer C.vsc_buffer_delete(messageInfoBuf)


    C.vscf_message_info_editor_pack(this.cCtx, messageInfoBuf)

    return messageInfoData[0:C.vsc_buffer_len(messageInfoBuf)] /* r7 */
}
