package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* CMS based serialization of the class "message info".
*/
type MessageInfoDerSerializer struct {
    IMessageInfoSerializer
    IMessageInfoFooterSerializer
    cCtx *C.vscf_message_info_der_serializer_t /*ct10*/
}

func (obj *MessageInfoDerSerializer) SetAsn1Reader (asn1Reader IAsn1Reader) {
    C.vscf_message_info_der_serializer_release_asn1_reader(obj.cCtx)
    C.vscf_message_info_der_serializer_use_asn1_reader(obj.cCtx, (*C.vscf_impl_t)(asn1Reader.ctx()))
}

func (obj *MessageInfoDerSerializer) SetAsn1Writer (asn1Writer IAsn1Writer) {
    C.vscf_message_info_der_serializer_release_asn1_writer(obj.cCtx)
    C.vscf_message_info_der_serializer_use_asn1_writer(obj.cCtx, (*C.vscf_impl_t)(asn1Writer.ctx()))
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *MessageInfoDerSerializer) SetupDefaults () {
    C.vscf_message_info_der_serializer_setup_defaults(obj.cCtx)

    return
}

/* Handle underlying C context. */
func (obj *MessageInfoDerSerializer) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
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

/*
* Release underlying C context.
*/
func (obj *MessageInfoDerSerializer) Delete () {
    C.vscf_message_info_der_serializer_delete(obj.cCtx)
}

func (obj *MessageInfoDerSerializer) GetPrefixLen () uint32 {
    return 32
}

/*
* Return buffer size enough to hold serialized message info.
*/
func (obj *MessageInfoDerSerializer) SerializedLen (messageInfo *MessageInfo) uint32 {
    proxyResult := /*pr4*/C.vscf_message_info_der_serializer_serialized_len(obj.cCtx, (*C.vscf_message_info_t)(messageInfo.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Serialize class "message info".
*/
func (obj *MessageInfoDerSerializer) Serialize (messageInfo *MessageInfo) []byte {
    outBuf, outBufErr := bufferNewBuffer(int(obj.SerializedLen(messageInfo) /* lg2 */))
    if outBufErr != nil {
        return nil
    }
    defer outBuf.Delete()


    C.vscf_message_info_der_serializer_serialize(obj.cCtx, (*C.vscf_message_info_t)(messageInfo.ctx()), outBuf.ctx)

    return outBuf.getData() /* r7 */
}

/*
* Read message info prefix from the given data, and if it is valid,
* return a length of bytes of the whole message info.
*
* Zero returned if length can not be determined from the given data,
* and this means that there is no message info at the data beginning.
*/
func (obj *MessageInfoDerSerializer) ReadPrefix (data []byte) uint32 {
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_message_info_der_serializer_read_prefix(obj.cCtx, dataData)

    return uint32(proxyResult) /* r9 */
}

/*
* Deserialize class "message info".
*/
func (obj *MessageInfoDerSerializer) Deserialize (data []byte) (*MessageInfo, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_message_info_der_serializer_deserialize(obj.cCtx, dataData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newMessageInfoWithCtx(proxyResult) /* r6 */, nil
}

/*
* Return buffer size enough to hold serialized message info footer.
*/
func (obj *MessageInfoDerSerializer) SerializedFooterLen (messageInfoFooter *MessageInfoFooter) uint32 {
    proxyResult := /*pr4*/C.vscf_message_info_der_serializer_serialized_footer_len(obj.cCtx, (*C.vscf_message_info_footer_t)(messageInfoFooter.ctx()))

    return uint32(proxyResult) /* r9 */
}

/*
* Serialize class "message info footer".
*/
func (obj *MessageInfoDerSerializer) SerializeFooter (messageInfoFooter *MessageInfoFooter) []byte {
    outBuf, outBufErr := bufferNewBuffer(int(obj.SerializedFooterLen(messageInfoFooter) /* lg2 */))
    if outBufErr != nil {
        return nil
    }
    defer outBuf.Delete()


    C.vscf_message_info_der_serializer_serialize_footer(obj.cCtx, (*C.vscf_message_info_footer_t)(messageInfoFooter.ctx()), outBuf.ctx)

    return outBuf.getData() /* r7 */
}

/*
* Deserialize class "message info footer".
*/
func (obj *MessageInfoDerSerializer) DeserializeFooter (data []byte) (*MessageInfoFooter, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_message_info_der_serializer_deserialize_footer(obj.cCtx, dataData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    return newMessageInfoFooterWithCtx(proxyResult) /* r6 */, nil
}
