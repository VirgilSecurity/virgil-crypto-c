package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* CMS based serialization of the class "message info".
*/
type MessageInfoDerSerializer struct {
    IMessageInfoSerializer
    IMessageInfoFooterSerializer
    ctx *C.vscf_impl_t
}

func (this MessageInfoDerSerializer) SetAsn1Reader (asn1Reader IAsn1Reader) {
    C.vscf_message_info_der_serializer_release_asn1_reader(this.ctx)
    C.vscf_message_info_der_serializer_use_asn1_reader(this.ctx, asn1Reader.Ctx())
}

func (this MessageInfoDerSerializer) SetAsn1Writer (asn1Writer IAsn1Writer) {
    C.vscf_message_info_der_serializer_release_asn1_writer(this.ctx)
    C.vscf_message_info_der_serializer_use_asn1_writer(this.ctx, asn1Writer.Ctx())
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (this MessageInfoDerSerializer) SetupDefaults () {
    C.vscf_message_info_der_serializer_setup_defaults(this.ctx)
}

/* Handle underlying C context. */
func (this MessageInfoDerSerializer) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewMessageInfoDerSerializer () *MessageInfoDerSerializer {
    ctx := C.vscf_message_info_der_serializer_new()
    return &MessageInfoDerSerializer {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessageInfoDerSerializerWithCtx (ctx *C.vscf_impl_t) *MessageInfoDerSerializer {
    return &MessageInfoDerSerializer {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewMessageInfoDerSerializerCopy (ctx *C.vscf_impl_t) *MessageInfoDerSerializer {
    return &MessageInfoDerSerializer {
        ctx: C.vscf_message_info_der_serializer_shallow_copy(ctx),
    }
}

func (this MessageInfoDerSerializer) getPrefixLen () int32 {
    return 32
}

/*
* Return buffer size enough to hold serialized message info.
*/
func (this MessageInfoDerSerializer) SerializedLen (messageInfo MessageInfo) int32 {
    proxyResult := C.vscf_message_info_der_serializer_serialized_len(this.ctx, messageInfo.Ctx())

    return proxyResult //r9
}

/*
* Serialize class "message info".
*/
func (this MessageInfoDerSerializer) Serialize (messageInfo MessageInfo) []byte {
    outCount := this.SerializedLen(messageInfo) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    C.vscf_message_info_der_serializer_serialize(this.ctx, messageInfo.Ctx(), outBuf)

    return outBuf.GetData() /* r7 */
}

/*
* Read message info prefix from the given data, and if it is valid,
* return a length of bytes of the whole message info.
*
* Zero returned if length can not be determined from the given data,
* and this means that there is no message info at the data beginning.
*/
func (this MessageInfoDerSerializer) ReadPrefix (data []byte) int32 {
    proxyResult := C.vscf_message_info_der_serializer_read_prefix(this.ctx, WrapData(data))

    return proxyResult //r9
}

/*
* Deserialize class "message info".
*/
func (this MessageInfoDerSerializer) Deserialize (data []byte) MessageInfo {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_message_info_der_serializer_deserialize(this.ctx, WrapData(data), &error)

    FoundationErrorHandleStatus(error.status)

    return *NewMessageInfoWithCtx(proxyResult) /* r6 */
}

/*
* Return buffer size enough to hold serialized message info footer.
*/
func (this MessageInfoDerSerializer) SerializedFooterLen (messageInfoFooter MessageInfoFooter) int32 {
    proxyResult := C.vscf_message_info_der_serializer_serialized_footer_len(this.ctx, messageInfoFooter.Ctx())

    return proxyResult //r9
}

/*
* Serialize class "message info footer".
*/
func (this MessageInfoDerSerializer) SerializeFooter (messageInfoFooter MessageInfoFooter) []byte {
    outCount := this.SerializedFooterLen(messageInfoFooter) /* lg2 */
    outBuf := NewBuffer(outCount)
    defer outBuf.Clear()


    C.vscf_message_info_der_serializer_serialize_footer(this.ctx, messageInfoFooter.Ctx(), outBuf)

    return outBuf.GetData() /* r7 */
}

/*
* Deserialize class "message info footer".
*/
func (this MessageInfoDerSerializer) DeserializeFooter (data []byte) MessageInfoFooter {
    error := C.vscf_error_t()
    C.vscf_error_reset(&error)

    proxyResult := C.vscf_message_info_der_serializer_deserialize_footer(this.ctx, WrapData(data), &error)

    FoundationErrorHandleStatus(error.status)

    return *NewMessageInfoFooterWithCtx(proxyResult) /* r6 */
}
