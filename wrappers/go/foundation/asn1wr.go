package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"
import unsafe "unsafe"


/*
* This is MbedTLS implementation of ASN.1 writer.
*/
type Asn1wr struct {
    cCtx *C.vscf_asn1wr_t /*ct10*/
}

/* Handle underlying C context. */
func (obj *Asn1wr) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewAsn1wr() *Asn1wr {
    ctx := C.vscf_asn1wr_new()
    obj := &Asn1wr {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newAsn1wrWithCtx(ctx *C.vscf_asn1wr_t /*ct10*/) *Asn1wr {
    obj := &Asn1wr {
        cCtx: ctx,
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newAsn1wrCopy(ctx *C.vscf_asn1wr_t /*ct10*/) *Asn1wr {
    obj := &Asn1wr {
        cCtx: C.vscf_asn1wr_shallow_copy(ctx),
    }
    runtime.SetFinalizer(obj, obj.Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *Asn1wr) Delete() {
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *Asn1wr) delete() {
    C.vscf_asn1wr_delete(obj.cCtx)
}

/*
* Reset all internal states and prepare to new ASN.1 writing operations.
*/
func (obj *Asn1wr) Reset(out []byte, outLen uint32) {
    C.vscf_asn1wr_reset(obj.cCtx, helperBytesToBytePtr(out)/*pa8*/, (C.size_t)(outLen)/*pa10*/)

    return
}

/*
* Finalize writing and forbid further operations.
*
* Note, that ASN.1 structure is always written to the buffer end, and
* if argument "do not adjust" is false, then data is moved to the
* beginning, otherwise - data is left at the buffer end.
*
* Returns length of the written bytes.
*/
func (obj *Asn1wr) Finish(doNotAdjust bool) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_finish(obj.cCtx, (C.bool)(doNotAdjust)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Returns pointer to the inner buffer.
*/
func (obj *Asn1wr) Bytes() unsafe.Pointer {
    proxyResult := /*pr4*/C.vscf_asn1wr_bytes(obj.cCtx)

    return unsafe.Pointer(proxyResult) /* r3 */
}

/*
* Returns total inner buffer length.
*/
func (obj *Asn1wr) Len() uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_len(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Returns how many bytes were already written to the ASN.1 structure.
*/
func (obj *Asn1wr) WrittenLen() uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_written_len(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Returns how many bytes are available for writing.
*/
func (obj *Asn1wr) UnwrittenLen() uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_unwritten_len(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Return true if status is not "success".
*/
func (obj *Asn1wr) HasError() bool {
    proxyResult := /*pr4*/C.vscf_asn1wr_has_error(obj.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Return error code.
*/
func (obj *Asn1wr) Status() error {
    proxyResult := /*pr4*/C.vscf_asn1wr_status(obj.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Move writing position backward for the given length.
* Return current writing position.
*/
func (obj *Asn1wr) Reserve(len uint32) unsafe.Pointer {
    proxyResult := /*pr4*/C.vscf_asn1wr_reserve(obj.cCtx, (C.size_t)(len)/*pa10*/)

    return unsafe.Pointer(proxyResult) /* r3 */
}

/*
* Write ASN.1 tag.
* Return count of written bytes.
*/
func (obj *Asn1wr) WriteTag(tag int32) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_tag(obj.cCtx, (C.int32_t)(tag)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write context-specific ASN.1 tag.
* Return count of written bytes.
*/
func (obj *Asn1wr) WriteContextTag(tag int32, len uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_context_tag(obj.cCtx, (C.int32_t)(tag)/*pa10*/, (C.size_t)(len)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write length of the following data.
* Return count of written bytes.
*/
func (obj *Asn1wr) WriteLen(len uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_len(obj.cCtx, (C.size_t)(len)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (obj *Asn1wr) WriteInt(value int32) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_int(obj.cCtx, (C.int32_t)(value)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (obj *Asn1wr) WriteInt8(value int8) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_int8(obj.cCtx, (C.int8_t)(value)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (obj *Asn1wr) WriteInt16(value int16) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_int16(obj.cCtx, (C.int16_t)(value)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (obj *Asn1wr) WriteInt32(value int32) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_int32(obj.cCtx, (C.int32_t)(value)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (obj *Asn1wr) WriteInt64(value int64) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_int64(obj.cCtx, (C.int64_t)(value)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (obj *Asn1wr) WriteUint(value uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_uint(obj.cCtx, (C.uint)(value)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (obj *Asn1wr) WriteUint8(value uint8) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_uint8(obj.cCtx, (C.uchar)(value)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (obj *Asn1wr) WriteUint16(value uint16) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_uint16(obj.cCtx, (C.ushort)(value)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (obj *Asn1wr) WriteUint32(value uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_uint32(obj.cCtx, (C.uint)(value)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (obj *Asn1wr) WriteUint64(value uint64) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_uint64(obj.cCtx, (C.uint64_t)(value)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: BOOLEAN.
* Return count of written bytes.
*/
func (obj *Asn1wr) WriteBool(value bool) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_bool(obj.cCtx, (C.bool)(value)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: NULL.
*/
func (obj *Asn1wr) WriteNull() uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_null(obj.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: OCTET STRING.
* Return count of written bytes.
*/
func (obj *Asn1wr) WriteOctetStr(value []byte) uint32 {
    valueData := helperWrapData (value)

    proxyResult := /*pr4*/C.vscf_asn1wr_write_octet_str(obj.cCtx, valueData)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: BIT STRING with all zero unused bits.
*
* Return count of written bytes.
*/
func (obj *Asn1wr) WriteOctetStrAsBitstring(value []byte) uint32 {
    valueData := helperWrapData (value)

    proxyResult := /*pr4*/C.vscf_asn1wr_write_octet_str_as_bitstring(obj.cCtx, valueData)

    return uint32(proxyResult) /* r9 */
}

/*
* Write raw data directly to the ASN.1 structure.
* Return count of written bytes.
* Note, use this method carefully.
*/
func (obj *Asn1wr) WriteData(data []byte) uint32 {
    dataData := helperWrapData (data)

    proxyResult := /*pr4*/C.vscf_asn1wr_write_data(obj.cCtx, dataData)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: UTF8String.
* Return count of written bytes.
*/
func (obj *Asn1wr) WriteUtf8Str(value []byte) uint32 {
    valueData := helperWrapData (value)

    proxyResult := /*pr4*/C.vscf_asn1wr_write_utf8_str(obj.cCtx, valueData)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: OID.
* Return count of written bytes.
*/
func (obj *Asn1wr) WriteOid(value []byte) uint32 {
    valueData := helperWrapData (value)

    proxyResult := /*pr4*/C.vscf_asn1wr_write_oid(obj.cCtx, valueData)

    return uint32(proxyResult) /* r9 */
}

/*
* Mark previously written data of given length as ASN.1 type: SEQUENCE.
* Return count of written bytes.
*/
func (obj *Asn1wr) WriteSequence(len uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_sequence(obj.cCtx, (C.size_t)(len)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Mark previously written data of given length as ASN.1 type: SET.
* Return count of written bytes.
*/
func (obj *Asn1wr) WriteSet(len uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_set(obj.cCtx, (C.size_t)(len)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}
