package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

/*
* Class represents group session message
*/
type GroupSessionMessage struct {
    cCtx *C.vscf_group_session_message_t /*ct2*/
}

/* Handle underlying C context. */
func (this GroupSessionMessage) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewGroupSessionMessage () *GroupSessionMessage {
    ctx := C.vscf_group_session_message_new()
    return &GroupSessionMessage {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newGroupSessionMessageWithCtx (ctx *C.vscf_group_session_message_t /*ct2*/) *GroupSessionMessage {
    return &GroupSessionMessage {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newGroupSessionMessageCopy (ctx *C.vscf_group_session_message_t /*ct2*/) *GroupSessionMessage {
    return &GroupSessionMessage {
        cCtx: C.vscf_group_session_message_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this GroupSessionMessage) close () {
    C.vscf_group_session_message_delete(this.cCtx)
}

/*
* Max message len
*/
func GroupSessionMessageGetMaxMessageLen () uint32 {
    return 30188
}

/*
* Message version
*/
func GroupSessionMessageGetMessageVersion () uint32 {
    return 1
}

/*
* Returns message type.
*/
func (this GroupSessionMessage) GetType () GroupMsgType {
    proxyResult := /*pr4*/C.vscf_group_session_message_get_type(this.cCtx)

    return GroupMsgType(proxyResult) /* r8 */
}

/*
* Returns session id.
* This method should be called only for group info type.
*/
func (this GroupSessionMessage) GetSessionId () []byte {
    proxyResult := /*pr4*/C.vscf_group_session_message_get_session_id(this.cCtx)

    return helperDataToBytes(proxyResult) /* r1 */
}

/*
* Returns message epoch.
*/
func (this GroupSessionMessage) GetEpoch () uint32 {
    proxyResult := /*pr4*/C.vscf_group_session_message_get_epoch(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Buffer len to serialize this class.
*/
func (this GroupSessionMessage) SerializeLen () uint32 {
    proxyResult := /*pr4*/C.vscf_group_session_message_serialize_len(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Serializes instance.
*/
func (this GroupSessionMessage) Serialize () []byte {
    outputCount := C.ulong(this.SerializeLen() /* lg2 */)
    outputMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outputCount))
    outputBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outputMemory[0]))
    outputData := outputMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outputBuf)
    C.vsc_buffer_use(outputBuf, (*C.byte)(unsafe.Pointer(&outputData[0])), outputCount)
    defer C.vsc_buffer_delete(outputBuf)


    C.vscf_group_session_message_serialize(this.cCtx, outputBuf)

    return outputData[0:C.vsc_buffer_len(outputBuf)] /* r7 */
}

/*
* Deserializes instance.
*/
func GroupSessionMessageDeserialize (input []byte) (*GroupSessionMessage, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    inputData := C.vsc_data((*C.uint8_t)(&input[0]), C.size_t(len(input)))

    proxyResult := /*pr4*/C.vscf_group_session_message_deserialize(inputData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newGroupSessionMessageWithCtx(proxyResult) /* r6 */, nil
}
