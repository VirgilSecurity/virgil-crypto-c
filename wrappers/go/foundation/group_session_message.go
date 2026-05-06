package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* Class represents group session message
*/
type GroupSessionMessage struct {
    cCtx *C.vscf_group_session_message_t
}
const (
    GroupSessionMessageMaxMessageLen uint = 30188
    GroupSessionMessageMessageVersion uint = 1
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
func newGroupSessionMessageWithCtx(ctx *C.vscf_group_session_message_t) *GroupSessionMessage {
    obj := &GroupSessionMessage {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*GroupSessionMessage).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newGroupSessionMessageCopy(ctx *C.vscf_group_session_message_t) *GroupSessionMessage {
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
    proxyResult := C.vscf_group_session_message_get_type(obj.cCtx)

    runtime.KeepAlive(obj)

    return GroupMsgType(proxyResult)
}

/*
* Returns session id.
* This method should be called only for group info type.
*/
func (obj *GroupSessionMessage) GetSessionId() []byte {
    proxyResult := C.vscf_group_session_message_get_session_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult)
}

/*
* Returns message epoch.
*/
func (obj *GroupSessionMessage) GetEpoch() uint32 {
    proxyResult := C.vscf_group_session_message_get_epoch(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint32(proxyResult)
}

/*
* Buffer len to serialize this class.
*/
func (obj *GroupSessionMessage) SerializeLen() uint {
    proxyResult := C.vscf_group_session_message_serialize_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult)
}

/*
* Serializes instance.
*/
func (obj *GroupSessionMessage) Serialize() []byte {
    outputBuf, outputBufErr := newBuffer(int(obj.SerializeLen()))
    if outputBufErr != nil {
        return nil
    }
    defer outputBuf.delete()


    C.vscf_group_session_message_serialize(obj.cCtx, outputBuf.ctx)

    runtime.KeepAlive(obj)

    return outputBuf.getData()
}

/*
* Deserializes instance.
*/
func (obj *GroupSessionMessage) Deserialize(input []byte) (*GroupSessionMessage, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)

    inputData := helperWrapData (input)

    proxyResult := C.vscf_group_session_message_deserialize(inputData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return newGroupSessionMessageWithCtx(proxyResult), nil
}
