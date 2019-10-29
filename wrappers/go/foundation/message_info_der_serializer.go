package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

/*
* CMS based serialization of the class "message info".
*/
type MessageInfoDerSerializer struct {
    IMessageInfoSerializer
    IMessageInfoFooterSerializer
    cCtx *C.vscf_message_info_der_serializer_t /*ct10*/
}

func (this MessageInfoDerSerializer) SetAsn1Reader (asn1Reader IAsn1Reader) {
    C.vscf_message_info_der_serializer_release_asn1_reader(this.cCtx)
    C.vscf_message_info_der_serializer_use_asn1_reader(this.cCtx, (*C.vscf_impl_t)(asn1Reader.ctx()))
}

func (this MessageInfoDerSerializer) SetAsn1Writer (asn1Writer IAsn1Writer) {
    C.vscf_message_info_der_serializer_release_asn1_writer(this.cCtx)
    C.vscf_message_info_der_serializer_use_asn1_writer(this.cCtx, (*C.vscf_impl_t)(asn1Writer.ctx()))
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this MessageInfoDerSerializer) SetupDefaults () {
    C.vscf_message_info_der_serializer_setup_defaults(this.cCtx)

    return
}

/* Handle underlying C context. */
func (this MessageInfoDerSerializer) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewMessageInfoDerSerializer () *MessageInfoDerSerializer {
    ctx := C.vscf_message_info_der_serializer_new()
    return &MessageInfoDerSerializer {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newMessageInfoDerSerializerWithCtx (ctx *C.vscf_message_info_der_serializer_t /*ct10*/) *MessageInfoDerSerializer {
    return &MessageInfoDerSerializer {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newMessageInfoDerSerializerCopy (ctx *C.vscf_message_info_der_serializer_t /*ct10*/) *MessageInfoDerSerializer {
    return &MessageInfoDerSerializer {
        cCtx: C.vscf_message_info_der_serializer_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this MessageInfoDerSerializer) close () {
    C.vscf_message_info_der_serializer_delete(this.cCtx)
}

func MessageInfoDerSerializerGetPrefixLen () uint32 {
    return 32
}

/*
* Return buffer size enough to hold serialized message info.
*/
func (this MessageInfoDerSerializer) SerializedLen (messageInfo *MessageInfo) uint32 {
    proxyResult := /*pr4*/C.vscf_message_info_der_serializer_serialized_len(this.cCtx, (*C.vscf_message_info_t)(messageInfo.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Serialize class "message info".
*/
func (this MessageInfoDerSerializer) Serialize (messageInfo *MessageInfo) []byte {
    outCount := C.ulong(this.SerializedLen(messageInfo) /* lg2 */)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)


    C.vscf_message_info_der_serializer_serialize(this.cCtx, (*C.vscf_message_info_t)(messageInfo.ctx()), outBuf)

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */
}

/*
* Read message info prefix from the given data, and if it is valid,
* return a length of bytes of the whole message info.
*
* Zero returned if length can not be determined from the given data,
* and this means that there is no message info at the data beginning.
*/
func (this MessageInfoDerSerializer) ReadPrefix (data []byte) uint32 {
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    proxyResult := /*pr4*/C.vscf_message_info_der_serializer_read_prefix(this.cCtx, dataData)

    return uint32(proxyResult) /* r9 */
}

/*
* Deserialize class "message info".
*/
func (this MessageInfoDerSerializer) Deserialize (data []byte) (*MessageInfo, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    proxyResult := /*pr4*/C.vscf_message_info_der_serializer_deserialize(this.cCtx, dataData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newMessageInfoWithCtx(proxyResult) /* r6 */, nil
}

/*
* Return buffer size enough to hold serialized message info footer.
*/
func (this MessageInfoDerSerializer) SerializedFooterLen (messageInfoFooter *MessageInfoFooter) uint32 {
    proxyResult := /*pr4*/C.vscf_message_info_der_serializer_serialized_footer_len(this.cCtx, (*C.vscf_message_info_footer_t)(messageInfoFooter.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Serialize class "message info footer".
*/
func (this MessageInfoDerSerializer) SerializeFooter (messageInfoFooter *MessageInfoFooter) []byte {
    outCount := C.ulong(this.SerializedFooterLen(messageInfoFooter) /* lg2 */)
    outMemory := make([]byte, int(C.vsc_buffer_ctx_size() + outCount))
    outBuf := (*C.vsc_buffer_t)(unsafe.Pointer(&outMemory[0]))
    outData := outMemory[int(C.vsc_buffer_ctx_size()):]
    C.vsc_buffer_init(outBuf)
    C.vsc_buffer_use(outBuf, (*C.byte)(unsafe.Pointer(&outData[0])), outCount)
    defer C.vsc_buffer_delete(outBuf)


    C.vscf_message_info_der_serializer_serialize_footer(this.cCtx, (*C.vscf_message_info_footer_t)(messageInfoFooter.ctx()), outBuf)

    return outData[0:C.vsc_buffer_len(outBuf)] /* r7 */
}

/*
* Deserialize class "message info footer".
*/
func (this MessageInfoDerSerializer) DeserializeFooter (data []byte) (*MessageInfoFooter, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    proxyResult := /*pr4*/C.vscf_message_info_der_serializer_deserialize_footer(this.cCtx, dataData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newMessageInfoFooterWithCtx(proxyResult) /* r6 */, nil
}
