package ratchet

// #include <virgil/crypto/ratchet/vscr_ratchet_public.h>
import "C"
import "runtime"


/*
* Class represents ratchet group message
*/
type RatchetGroupMessage struct {
    cCtx *C.vscr_ratchet_group_message_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *RatchetGroupMessage) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewRatchetGroupMessage() *RatchetGroupMessage {
    ctx := C.vscr_ratchet_group_message_new()
    obj := &RatchetGroupMessage {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRatchetGroupMessageWithCtx(ctx *C.vscr_ratchet_group_message_t /*ct2*/) *RatchetGroupMessage {
    obj := &RatchetGroupMessage {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRatchetGroupMessageCopy(ctx *C.vscr_ratchet_group_message_t /*ct2*/) *RatchetGroupMessage {
    obj := &RatchetGroupMessage {
        cCtx: C.vscr_ratchet_group_message_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *RatchetGroupMessage) Delete() {
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *RatchetGroupMessage) delete() {
    C.vscr_ratchet_group_message_delete(obj.cCtx)
}

/*
* Returns message type.
*/
func (obj *RatchetGroupMessage) GetType() GroupMsgType {
    proxyResult := /*pr4*/C.vscr_ratchet_group_message_get_type(obj.cCtx)

    return GroupMsgType(proxyResult) /* r8 */
}

/*
* Returns session id.
* This method should be called only for group info type.
*/
func (obj *RatchetGroupMessage) GetSessionId() []byte {
    proxyResult := /*pr4*/C.vscr_ratchet_group_message_get_session_id(obj.cCtx)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Returns message counter in current epoch.
*/
func (obj *RatchetGroupMessage) GetCounter() uint32 {
    proxyResult := /*pr4*/C.vscr_ratchet_group_message_get_counter(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Returns message epoch.
*/
func (obj *RatchetGroupMessage) GetEpoch() uint32 {
    proxyResult := /*pr4*/C.vscr_ratchet_group_message_get_epoch(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Buffer len to serialize this class.
*/
func (obj *RatchetGroupMessage) SerializeLen() uint32 {
    proxyResult := /*pr4*/C.vscr_ratchet_group_message_serialize_len(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Serializes instance.
*/
func (obj *RatchetGroupMessage) Serialize() []byte {
    outputBuf, outputBufErr := bufferNewBuffer(int(obj.SerializeLen() /* lg2 */))
    if outputBufErr != nil {
        return nil
    }
    defer outputBuf.Delete()


    C.vscr_ratchet_group_message_serialize(obj.cCtx, outputBuf.ctx)

    return outputBuf.getData() /* r7 */
}

/*
* Deserializes instance.
*/
func RatchetGroupMessageDeserialize(input []byte) (*RatchetGroupMessage, error) {
    var error C.vscr_error_t
    C.vscr_error_reset(&error)
    inputData := helperWrapData (input)

    proxyResult := /*pr4*/C.vscr_ratchet_group_message_deserialize(inputData, &error)

    err := RatchetErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newRatchetGroupMessageWithCtx(proxyResult) /* r6 */, nil
}
