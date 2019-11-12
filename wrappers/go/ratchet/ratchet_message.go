package ratchet

// #include <virgil/crypto/ratchet/vscr_ratchet_public.h>
import "C"


/*
* Class represents ratchet message
*/
type RatchetMessage struct {
    cCtx *C.vscr_ratchet_message_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *RatchetMessage) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewRatchetMessage () *RatchetMessage {
    ctx := C.vscr_ratchet_message_new()
    return &RatchetMessage {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRatchetMessageWithCtx (ctx *C.vscr_ratchet_message_t /*ct2*/) *RatchetMessage {
    return &RatchetMessage {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRatchetMessageCopy (ctx *C.vscr_ratchet_message_t /*ct2*/) *RatchetMessage {
    return &RatchetMessage {
        cCtx: C.vscr_ratchet_message_shallow_copy(ctx),
    }
}

/*
* Release underlying C context.
*/
func (obj *RatchetMessage) Delete () {
    C.vscr_ratchet_message_delete(obj.cCtx)
}

/*
* Returns message type.
*/
func (obj *RatchetMessage) GetType () MsgType {
    proxyResult := /*pr4*/C.vscr_ratchet_message_get_type(obj.cCtx)

    return MsgType(proxyResult) /* r8 */
}

/*
* Returns message counter in current asymmetric ratchet round.
*/
func (obj *RatchetMessage) GetCounter () uint32 {
    proxyResult := /*pr4*/C.vscr_ratchet_message_get_counter(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Returns long-term public key, if message is prekey message.
*/
func (obj *RatchetMessage) GetLongTermPublicKey () []byte {
    proxyResult := /*pr4*/C.vscr_ratchet_message_get_long_term_public_key(obj.cCtx)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Returns one-time public key, if message is prekey message and if one-time key is present, empty result otherwise.
*/
func (obj *RatchetMessage) GetOneTimePublicKey () []byte {
    proxyResult := /*pr4*/C.vscr_ratchet_message_get_one_time_public_key(obj.cCtx)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Buffer len to serialize this class.
*/
func (obj *RatchetMessage) SerializeLen () uint32 {
    proxyResult := /*pr4*/C.vscr_ratchet_message_serialize_len(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Serializes instance.
*/
func (obj *RatchetMessage) Serialize () []byte {
    outputBuf, outputBufErr := bufferNewBuffer(int(obj.SerializeLen() /* lg2 */))
    if outputBufErr != nil {
        return nil
    }
    defer outputBuf.Delete()


    C.vscr_ratchet_message_serialize(obj.cCtx, outputBuf.ctx)

    return outputBuf.getData() /* r7 */
}

/*
* Deserializes instance.
*/
func RatchetMessageDeserialize (input []byte) (*RatchetMessage, error) {
    var error C.vscr_error_t
    C.vscr_error_reset(&error)
    inputData := helperWrapData (input)

    proxyResult := /*pr4*/C.vscr_ratchet_message_deserialize(inputData, &error)

    err := RatchetErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newRatchetMessageWithCtx(proxyResult) /* r6 */, nil
}
