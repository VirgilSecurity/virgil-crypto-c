package ratchet

// #include <virgil/crypto/ratchet/vscr_ratchet_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Class represents ratchet message
*/
type RatchetMessage struct {
    cCtx *C.vscr_ratchet_message_t
}

/* Handle underlying C context. */
func (obj *RatchetMessage) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewRatchetMessage() *RatchetMessage {
    ctx := C.vscr_ratchet_message_new()
    obj := &RatchetMessage {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*RatchetMessage).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRatchetMessageWithCtx(ctx *C.vscr_ratchet_message_t) *RatchetMessage {
    obj := &RatchetMessage {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*RatchetMessage).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRatchetMessageCopy(ctx *C.vscr_ratchet_message_t) *RatchetMessage {
    obj := &RatchetMessage {
        cCtx: C.vscr_ratchet_message_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*RatchetMessage).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *RatchetMessage) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *RatchetMessage) delete() {
    C.vscr_ratchet_message_delete(obj.cCtx)
}

/*
* Returns message type.
*/
func (obj *RatchetMessage) GetType() MsgType {
    proxyResult := C.vscr_ratchet_message_get_type(obj.cCtx)

    runtime.KeepAlive(obj)

    return MsgType(proxyResult)
}

/*
* Returns message counter in current asymmetric ratchet round.
*/
func (obj *RatchetMessage) GetCounter() uint32 {
    proxyResult := C.vscr_ratchet_message_get_counter(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint32(proxyResult)
}

/*
* Returns long-term public key, if message is prekey message.
*/
func (obj *RatchetMessage) GetSenderIdentityKeyId() []byte {
    proxyResult := C.vscr_ratchet_message_get_sender_identity_key_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult)
}

/*
* Returns long-term public key, if message is prekey message.
*/
func (obj *RatchetMessage) GetReceiverIdentityKeyId() []byte {
    proxyResult := C.vscr_ratchet_message_get_receiver_identity_key_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult)
}

/*
* Returns long-term public key, if message is prekey message.
*/
func (obj *RatchetMessage) GetReceiverLongTermKeyId() []byte {
    proxyResult := C.vscr_ratchet_message_get_receiver_long_term_key_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult)
}

/*
* Returns one-time public key, if message is prekey message and if one-time key is present, empty result otherwise.
*/
func (obj *RatchetMessage) GetReceiverOneTimeKeyId() []byte {
    proxyResult := C.vscr_ratchet_message_get_receiver_one_time_key_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult)
}

/*
* Buffer len to serialize this class.
*/
func (obj *RatchetMessage) SerializeLen() uint {
    proxyResult := C.vscr_ratchet_message_serialize_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Serializes instance.
*/
func (obj *RatchetMessage) Serialize() []byte {
    outputBuf, outputBufErr := newBuffer(int(obj.SerializeLen()))
    if outputBufErr != nil {
        return nil
    }
    defer outputBuf.delete()


    C.vscr_ratchet_message_serialize(obj.cCtx, outputBuf.ctx)

    runtime.KeepAlive(obj)

    return outputBuf.getData()
}

/*
* Deserializes instance.
*/
func (obj *RatchetMessage) Deserialize(input []byte) (*RatchetMessage, error) {
    var error C.vscr_error_t
    C.vscr_error_reset(&error)

    inputData := helperWrapData (input)

    proxyResult := C.vscr_ratchet_message_deserialize(inputData, &error)

    err := RatchetErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return newRatchetMessageWithCtx(proxyResult), nil
}
