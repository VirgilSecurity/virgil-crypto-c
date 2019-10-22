package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Add and/or remove recipients and it's parameters within message info.
*
* Usage:
* 1. Unpack binary message info that was obtained from RecipientCipher.
* 2. Add and/or remove key recipients.
* 3. Pack MessagInfo to the binary data.
*/
type MessageInfoEditor struct {
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this MessageInfoEditor) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewMessageInfoEditor () *MessageInfoEditor {
    ctx := C.vscf_message_info_editor_new()
    return &MessageInfoEditor {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessageInfoEditorWithCtx (ctx *C.vscf_impl_t) *MessageInfoEditor {
    return &MessageInfoEditor {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessageInfoEditorCopy (ctx *C.vscf_impl_t) *MessageInfoEditor {
    return &MessageInfoEditor {
        ctx: C.vscf_message_info_editor_shallow_copy(ctx),
    }
}

func (this MessageInfoEditor) SetRandom (random IRandom) {
    C.vscf_message_info_editor_release_random(this.ctx)
    C.vscf_message_info_editor_use_random(this.ctx, random.Ctx())
}

/*
* Set dependencies to it's defaults.
*/
func (this MessageInfoEditor) SetupDefaults () {
    proxyResult := C.vscf_message_info_editor_setup_defaults(this.ctx)

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Unpack serialized message info.
*
* Note that recipients can only be removed but not added.
* Note, use "unlock" method to be able to add new recipients as well.
*/
func (this MessageInfoEditor) Unpack (messageInfoData []byte) {
    proxyResult := C.vscf_message_info_editor_unpack(this.ctx, WrapData(messageInfoData))

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Decrypt encryption key this allows adding new recipients.
*/
func (this MessageInfoEditor) Unlock (ownerRecipientId []byte, ownerPrivateKey IPrivateKey) {
    proxyResult := C.vscf_message_info_editor_unlock(this.ctx, WrapData(ownerRecipientId), ownerPrivateKey.Ctx())

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Add recipient defined with id and public key.
*/
func (this MessageInfoEditor) AddKeyRecipient (recipientId []byte, publicKey IPublicKey) {
    proxyResult := C.vscf_message_info_editor_add_key_recipient(this.ctx, WrapData(recipientId), publicKey.Ctx())

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Remove recipient with a given id.
* Return false if recipient with given id was not found.
*/
func (this MessageInfoEditor) RemoveKeyRecipient (recipientId []byte) bool {
    proxyResult := C.vscf_message_info_editor_remove_key_recipient(this.ctx, WrapData(recipientId))

    return proxyResult //r9
}

/*
* Remove all existent recipients.
*/
func (this MessageInfoEditor) RemoveAll () {
    C.vscf_message_info_editor_remove_all(this.ctx)
}

/*
* Return length of serialized message info.
* Actual length can be obtained right after applying changes.
*/
func (this MessageInfoEditor) PackedLen () int32 {
    proxyResult := C.vscf_message_info_editor_packed_len(this.ctx)

    return proxyResult //r9
}

/*
* Return serialized message info.
* Precondition: this method can be called after "apply".
*/
func (this MessageInfoEditor) Pack () []byte {
    messageInfoCount := this.PackedLen() /* lg2 */
    messageInfoBuf := NewBuffer(messageInfoCount)
    defer messageInfoBuf.Clear()


    C.vscf_message_info_editor_pack(this.ctx, messageInfoBuf)

    return messageInfoBuf.GetData() /* r7 */
}
