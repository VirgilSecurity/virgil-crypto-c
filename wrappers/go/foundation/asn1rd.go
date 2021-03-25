package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"
import "runtime"


/*
* This is MbedTLS implementation of ASN.1 reader.
*/
type Asn1rd struct {
    cCtx *C.vscf_asn1rd_t /*ct10*/
}

/* Handle underlying C context. */
func (obj *Asn1rd) Ctx() uintptr {
    return uintptr(unsafe.Pointer(obj.cCtx))
}

func NewAsn1rd() *Asn1rd {
    ctx := C.vscf_asn1rd_new()
    obj := &Asn1rd {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Asn1rd).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewAsn1rdWithCtx(pointer unsafe.Pointer) *Asn1rd {
    ctx := (*C.vscf_asn1rd_t /*ct10*/)(pointer)
    obj := &Asn1rd {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, (*Asn1rd).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewAsn1rdCopy(pointer unsafe.Pointer) *Asn1rd {
    ctx := (*C.vscf_asn1rd_t /*ct10*/)(pointer)
    obj := &Asn1rd {
        cCtx: C.vscf_asn1rd_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, (*Asn1rd).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Asn1rd) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *Asn1rd) delete() {
    C.vscf_asn1rd_delete(obj.cCtx)
}

/*
* Reset all internal states and prepare to new ASN.1 reading operations.
*/
func (obj *Asn1rd) Reset(data []byte) {
    dataData := helperWrapData (data)

    C.vscf_asn1rd_reset(obj.cCtx, dataData)

    runtime.KeepAlive(obj)

    return
}

/*
* Return length in bytes how many bytes are left for reading.
*/
func (obj *Asn1rd) LeftLen() uint {
    proxyResult := /*pr4*/C.vscf_asn1rd_left_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Return true if status is not "success".
*/
func (obj *Asn1rd) HasError() bool {
    proxyResult := /*pr4*/C.vscf_asn1rd_has_error(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Return error code.
*/
func (obj *Asn1rd) Status() error {
    proxyResult := /*pr4*/C.vscf_asn1rd_status(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    runtime.KeepAlive(obj)

    return nil
}

/*
* Get tag of the current ASN.1 element.
*/
func (obj *Asn1rd) GetTag() int32 {
    proxyResult := /*pr4*/C.vscf_asn1rd_get_tag(obj.cCtx)

    runtime.KeepAlive(obj)

    return int32(proxyResult) /* r9 */
}

/*
* Get length of the current ASN.1 element.
*/
func (obj *Asn1rd) GetLen() uint {
    proxyResult := /*pr4*/C.vscf_asn1rd_get_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Get length of the current ASN.1 element with tag and length itself.
*/
func (obj *Asn1rd) GetDataLen() uint {
    proxyResult := /*pr4*/C.vscf_asn1rd_get_data_len(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: TAG.
* Return element length.
*/
func (obj *Asn1rd) ReadTag(tag int32) uint {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_tag(obj.cCtx, (C.int32_t)(tag)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: context-specific TAG.
* Return element length.
* Return 0 if current position do not points to the requested tag.
*/
func (obj *Asn1rd) ReadContextTag(tag int32) uint {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_context_tag(obj.cCtx, (C.int32_t)(tag)/*pa10*/)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: INTEGER.
*/
func (obj *Asn1rd) ReadInt() int32 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_int(obj.cCtx)

    runtime.KeepAlive(obj)

    return int32(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: INTEGER.
*/
func (obj *Asn1rd) ReadInt8() int8 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_int8(obj.cCtx)

    runtime.KeepAlive(obj)

    return int8(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: INTEGER.
*/
func (obj *Asn1rd) ReadInt16() int16 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_int16(obj.cCtx)

    runtime.KeepAlive(obj)

    return int16(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: INTEGER.
*/
func (obj *Asn1rd) ReadInt32() int32 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_int32(obj.cCtx)

    runtime.KeepAlive(obj)

    return int32(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: INTEGER.
*/
func (obj *Asn1rd) ReadInt64() int64 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_int64(obj.cCtx)

    runtime.KeepAlive(obj)

    return int64(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: INTEGER.
*/
func (obj *Asn1rd) ReadUint() uint32 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_uint(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint32(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: INTEGER.
*/
func (obj *Asn1rd) ReadUint8() uint8 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_uint8(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint8(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: INTEGER.
*/
func (obj *Asn1rd) ReadUint16() uint16 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_uint16(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint16(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: INTEGER.
*/
func (obj *Asn1rd) ReadUint32() uint32 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_uint32(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint32(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: INTEGER.
*/
func (obj *Asn1rd) ReadUint64() uint64 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_uint64(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint64(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: BOOLEAN.
*/
func (obj *Asn1rd) ReadBool() bool {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_bool(obj.cCtx)

    runtime.KeepAlive(obj)

    return bool(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: NULL.
*/
func (obj *Asn1rd) ReadNull() {
    C.vscf_asn1rd_read_null(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Read ASN.1 type: NULL, only if it exists.
* Note, this method is safe to call even no more data is left for reading.
*/
func (obj *Asn1rd) ReadNullOptional() {
    C.vscf_asn1rd_read_null_optional(obj.cCtx)

    runtime.KeepAlive(obj)

    return
}

/*
* Read ASN.1 type: OCTET STRING.
*/
func (obj *Asn1rd) ReadOctetStr() []byte {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_octet_str(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Read ASN.1 type: BIT STRING.
*/
func (obj *Asn1rd) ReadBitstringAsOctetStr() []byte {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_bitstring_as_octet_str(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Read ASN.1 type: UTF8String.
*/
func (obj *Asn1rd) ReadUtf8Str() []byte {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_utf8_str(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Read ASN.1 type: OID.
*/
func (obj *Asn1rd) ReadOid() []byte {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_oid(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Read raw data of given length.
*/
func (obj *Asn1rd) ReadData(len uint) []byte {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_data(obj.cCtx, (C.size_t)(len)/*pa10*/)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Read ASN.1 type: SEQUENCE.
* Return element length.
*/
func (obj *Asn1rd) ReadSequence() uint {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_sequence(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: SET.
* Return element length.
*/
func (obj *Asn1rd) ReadSet() uint {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_set(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint(proxyResult) /* r9 */
}
