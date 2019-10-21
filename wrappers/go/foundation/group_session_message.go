package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Class represents group session message
*/
type GroupSessionMessage struct {
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this GroupSessionMessage) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewGroupSessionMessage () *GroupSessionMessage {
    ctx := C.vscf_group_session_message_new()
    return &GroupSessionMessage {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewGroupSessionMessageWithCtx (ctx *C.vscf_impl_t) *GroupSessionMessage {
    return &GroupSessionMessage {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewGroupSessionMessageCopy (ctx *C.vscf_impl_t) *GroupSessionMessage {
    return &GroupSessionMessage {
        ctx: C.vscf_group_session_message_shallow_copy(ctx),
    }
}

/*
* Max message len
*/
func (this GroupSessionMessage) getMaxMessageLen () int32 {
    return 30188
}

/*
* Message version
*/
func (this GroupSessionMessage) getMessageVersion () int32 {
    return 1
}

/*
* Returns message type.
*/
func (this GroupSessionMessage) GetType () GroupMsgType {
    proxyResult := C.vscf_group_session_message_get_type(this.ctx)

    return GroupMsgType(proxyResult) /* r8 */
}

/*
* Returns session id.
* This method should be called only for group info type.
*/
func (this GroupSessionMessage) GetSessionId () []byte {
    proxyResult := C.vscf_group_session_message_get_session_id(this.ctx)

    return ExtractData(proxyResult) /* r1 */
}

/*
* Returns message epoch.
*/
func (this GroupSessionMessage) GetEpoch () uint32 {
    proxyResult := C.vscf_group_session_message_get_epoch(this.ctx)

    return proxyResult //r9
}

/*
* Buffer len to serialize this class.
*/
func (this GroupSessionMessage) SerializeLen () int32 {
    proxyResult := C.vscf_group_session_message_serialize_len(this.ctx)

    return proxyResult //r9
}

/*
* Serializes instance.
*/
func (this GroupSessionMessage) Serialize () []byte {
    outputCount := this.SerializeLen() /* lg2 */
    outputBuf := NewBuffer(outputCount)
    defer outputBuf.Clear()


    C.vscf_group_session_message_serialize(this.ctx, outputBuf)

    return outputBuf.GetData() /* r7 */
}

/*
* Deserializes instance.
*/
func GroupSessionMessageDeserialize (input []byte) GroupSessionMessage {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_group_session_message_deserialize(WrapData(input), &error)

    FoundationErrorHandleStatus(error.status)

    return *NewGroupSessionMessageWithCtx(proxyResult) /* r6 */
}
