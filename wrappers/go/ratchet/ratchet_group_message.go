package ratchet

// #include <virgil/crypto/ratchet/vscr_ratchet_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Class represents ratchet group message
*/
type RatchetGroupMessage struct {
    cCtx *C.vscr_ratchet_group_message_t /*ct2*/
}

/* Handle underlying C context. */
func (obj *RatchetGroupMessage) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewRatchetGroupMessage() *RatchetGroupMessage {
    ctx := C.vscr_ratchet_group_message_new()
    obj := &RatchetGroupMessage {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*RatchetGroupMessage).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRatchetGroupMessageWithCtx(ctx *C.vscr_ratchet_group_message_t /*ct2*/) *RatchetGroupMessage {
    obj := &RatchetGroupMessage {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*RatchetGroupMessage).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newRatchetGroupMessageCopy(ctx *C.vscr_ratchet_group_message_t /*ct2*/) *RatchetGroupMessage {
    obj := &RatchetGroupMessage {
        cCtx: C.vscr_ratchet_group_message_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*RatchetGroupMessage).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *RatchetGroupMessage) Delete() {
    if obj == nil {
        return
    }
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

    runtime.KeepAlive(obj)

    return GroupMsgType(proxyResult) /* r8 */
}

/*
* Returns session id.
* This method should be called only for group info type.
*/
func (obj *RatchetGroupMessage) GetSessionId() []byte {
    proxyResult := /*pr4*/C.vscr_ratchet_group_message_get_session_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Returns message counter in current epoch.
*/
func (obj *RatchetGroupMessage) GetCounter() uint32 {
    proxyResult := /*pr4*/C.vscr_ratchet_group_message_get_counter(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint32(proxyResult) /* r9 */
}

/*
* Returns message epoch.
*/
func (obj *RatchetGroupMessage) GetEpoch() uint32 {
    proxyResult := /*pr4*/C.vscr_ratchet_group_message_get_epoch(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint32(proxyResult) /* r9 */
}

/*
* Buffer len to serialize this class.
*/
func (obj *RatchetGroupMessage) SerializeLen() uint32 {
    proxyResult := /*pr4*/C.vscr_ratchet_group_message_serialize_len(obj.cCtx)

    runtime.KeepAlive(obj)

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

    runtime.KeepAlive(obj)

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

    runtime.KeepAlive(error)

    return newRatchetGroupMessageWithCtx(proxyResult) /* r6 */, nil
}
