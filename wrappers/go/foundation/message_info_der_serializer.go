package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* CMS based serialization of the class "message info".
*/
type MessageInfoDerSerializer struct {
    cCtx *C.vscf_message_info_der_serializer_t /*ct10*/
}

func (obj *MessageInfoDerSerializer) SetAsn1Reader(asn1Reader Asn1Reader) {
    C.vscf_message_info_der_serializer_release_asn1_reader(obj.cCtx)
    C.vscf_message_info_der_serializer_use_asn1_reader(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(asn1Reader.Ctx())))

    runtime.KeepAlive(asn1Reader)
    runtime.KeepAlive(obj)
}

func (obj *MessageInfoDerSerializer) SetAsn1Writer(asn1Writer Asn1Writer) {
    C.vscf_message_info_der_serializer_release_asn1_writer(obj.cCtx)
    C.vscf_message_info_der_serializer_use_asn1_writer(obj.cCtx, (*C.vscf_impl_t)(unsafe.Pointer(asn1Writer.Ctx())))

    runtime.KeepAlive(asn1Writer)
    runtime.KeepAlive(obj)
}

/*
* Setup predefined values to the uninitialized class dependencies.
*/
func (obj *MessageInfoDerSerializer) SetupDefaults() {
    C.vscf_message_info_der_serializer_setup_defaults(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/* Handle underlying C context. */
func (obj *MessageInfoDerSerializer) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewMessageInfoDerSerializer() *MessageInfoDerSerializer {
    ctx := C.vscf_message_info_der_serializer_new()
    obj := &MessageInfoDerSerializer {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MessageInfoDerSerializer).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newMessageInfoDerSerializerWithCtx(ctx *C.vscf_message_info_der_serializer_t /*ct10*/) *MessageInfoDerSerializer {
    obj := &MessageInfoDerSerializer {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*MessageInfoDerSerializer).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newMessageInfoDerSerializerCopy(ctx *C.vscf_message_info_der_serializer_t /*ct10*/) *MessageInfoDerSerializer {
    obj := &MessageInfoDerSerializer {
        cCtx: C.vscf_message_info_der_serializer_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*MessageInfoDerSerializer).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *MessageInfoDerSerializer) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *MessageInfoDerSerializer) delete() {
    C.vscf_message_info_der_serializer_delete(obj.cCtx)
}

func (obj *MessageInfoDerSerializer) GetPrefixLen() uint {
    return 32
}

/*
* Return buffer size enough to hold serialized message info.
*/
func (obj *MessageInfoDerSerializer) SerializedLen(messageInfo *MessageInfo) uint {
    proxyResult := /*pr4*/C.vscf_message_info_der_serializer_serialized_len(obj.cCtx, (*C.vscf_message_info_t)(unsafe.Pointer(messageInfo.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(messageInfo)

    return uint(proxyResult) /* r9 */
}

/*
* Serialize class "message info".
*/
func (obj *MessageInfoDerSerializer) Serialize(messageInfo *MessageInfo) []byte {
    outBuf, outBufErr := newBuffer(int(obj.SerializedLen(messageInfo) /* lg2 */))
    if outBufErr != nil {
        return nil
    }
    defer outBuf.delete()


    C.vscf_message_info_der_serializer_serialize(obj.cCtx, (*C.vscf_message_info_t)(unsafe.Pointer(messageInfo.Ctx())), outBuf.ctx)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(messageInfo)

    return outBuf.getData() /* r7 */
}

/*
* Read message info prefix from the given data, and if it is valid,
* return a length of bytes of the whole message info.
*
* Zero returned if length can not be determined from the given data,
* and this means that there is no message info at the data beginning.
*/
func (obj *MessageInfoDerSerializer) ReadPrefix(data []byte) uint {
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_message_info_der_serializer_read_prefix(obj.cCtx, dataData)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Deserialize class "message info".
*/
func (obj *MessageInfoDerSerializer) Deserialize(data []byte) (*MessageInfo, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_message_info_der_serializer_deserialize(obj.cCtx, dataData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return newMessageInfoWithCtx(proxyResult) /* r6 */, nil
}

/*
* Return buffer size enough to hold serialized message info footer.
*/
func (obj *MessageInfoDerSerializer) SerializedFooterLen(messageInfoFooter *MessageInfoFooter) uint {
    proxyResult := /*pr4*/C.vscf_message_info_der_serializer_serialized_footer_len(obj.cCtx, (*C.vscf_message_info_footer_t)(unsafe.Pointer(messageInfoFooter.Ctx())))

    runtime.KeepAlive(obj)

    runtime.KeepAlive(messageInfoFooter)

    return uint(proxyResult) /* r9 */
}

/*
* Serialize class "message info footer".
*/
func (obj *MessageInfoDerSerializer) SerializeFooter(messageInfoFooter *MessageInfoFooter) []byte {
    outBuf, outBufErr := newBuffer(int(obj.SerializedFooterLen(messageInfoFooter) /* lg2 */))
    if outBufErr != nil {
        return nil
    }
    defer outBuf.delete()


    C.vscf_message_info_der_serializer_serialize_footer(obj.cCtx, (*C.vscf_message_info_footer_t)(unsafe.Pointer(messageInfoFooter.Ctx())), outBuf.ctx)

    runtime.KeepAlive(obj)

    runtime.KeepAlive(messageInfoFooter)

    return outBuf.getData() /* r7 */
}

/*
* Deserialize class "message info footer".
*/
func (obj *MessageInfoDerSerializer) DeserializeFooter(data []byte) (*MessageInfoFooter, error) {
    var error C.vscf_error_t
    C.vscf_error_reset(&error)
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_message_info_der_serializer_deserialize_footer(obj.cCtx, dataData, &error)

    err := FoundationErrorHandleStatus(error.status)
    if err != nil {
        return nil, err
    }

    runtime.KeepAlive(obj)

    return newMessageInfoFooterWithCtx(proxyResult) /* r6 */, nil
}
