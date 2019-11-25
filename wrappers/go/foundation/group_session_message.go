package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Class represents group session message
*/
type GroupSessionMessage struct {
    cCtx *C.vscf_group_session_message_t /*ct2*/
}
const (
    /*
    * Max message len
    */
    GroupSessionMessageMaxMessageLen uint32 = 30188
    /*
    * Message version
    */
    GroupSessionMessageMessageVersion uint32 = 1
)

/* Handle underlying C context. */
func (obj *GroupSessionMessage) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewGroupSessionMessage() *GroupSessionMessage {
    ctx := C.vscf_group_session_message_new()
    obj := &GroupSessionMessage {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*GroupSessionMessage).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newGroupSessionMessageWithCtx(ctx *C.vscf_group_session_message_t /*ct2*/) *GroupSessionMessage {
    obj := &GroupSessionMessage {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*GroupSessionMessage).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newGroupSessionMessageCopy(ctx *C.vscf_group_session_message_t /*ct2*/) *GroupSessionMessage {
    obj := &GroupSessionMessage {
        cCtx: C.vscf_group_session_message_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*GroupSessionMessage).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *GroupSessionMessage) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *GroupSessionMessage) delete() {
    C.vscf_group_session_message_delete(obj.cCtx)
}

/*
* Returns message type.
*/
func (obj *GroupSessionMessage) GetType() GroupMsgType {
    proxyResult := /*pr4*/C.vscf_group_session_message_get_type(obj.cCtx)

    runtime.KeepAlive(obj)

    return GroupMsgType(proxyResult) /* r8 */
}

/*
* Returns session id.
* This method should be called only for group info type.
*/
func (obj *GroupSessionMessage) GetSessionId() []byte {
    proxyResult := /*pr4*/C.vscf_group_session_message_get_session_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Returns message epoch.
*/
func (obj *GroupSessionMessage) GetEpoch() uint32 {
    proxyResult := /*pr4*/C.vscf_group_session_message_get_epoch(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint32(proxyResult) /* r9 */
}

/*
* Buffer len to serialize this class.
*/
func (obj *GroupSessionMessage) SerializeLen() uint32 {
    proxyResult := /*pr4*/C.vscf_group_session_message_serialize_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint32(proxyResult) /* r9 */
}

/*
* Serializes instance.
*/
func (obj *GroupSessionMessage) Serialize() []byte {
    outputBuf, outputBufErr := bufferNewBuffer(int(obj.SerializeLen() /* lg2 */))
    if outputBufErr != nil {
        return nil
    }
    defer outputBuf.Delete()


    C.vscf_group_session_message_serialize(obj.cCtx, outputBuf.ctx)

    runtime.KeepAlive(obj)

    return outputBuf.getData() /* r7 */
}

/*
* Deserializes instance.
*/
func GroupSessionMessageDeserialize(input []byte) (*GroupSessionMessage, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    inputData := helperWrapData (input)

    proxyResult := /*pr4*/C.vscf_group_session_message_deserialize(inputData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(error)

    return newGroupSessionMessageWithCtx(proxyResult) /* r6 */, nil
}
