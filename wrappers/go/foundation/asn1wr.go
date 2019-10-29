package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import unsafe "unsafe"

/*
* This is MbedTLS implementation of ASN.1 writer.
*/
type Asn1wr struct {
    IAsn1Writer
    cCtx *C.vscf_asn1wr_t /*ct10*/
}

/* Handle underlying C context. */
func (this Asn1wr) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewAsn1wr () *Asn1wr {
    ctx := C.vscf_asn1wr_new()
    return &Asn1wr {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newAsn1wrWithCtx (ctx *C.vscf_asn1wr_t /*ct10*/) *Asn1wr {
    return &Asn1wr {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newAsn1wrCopy (ctx *C.vscf_asn1wr_t /*ct10*/) *Asn1wr {
    return &Asn1wr {
        cCtx: C.vscf_asn1wr_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this Asn1wr) close () {
    C.vscf_asn1wr_delete(this.cCtx)
}

/*
* Reset all internal states and prepare to new ASN.1 writing operations.
*/
func (this Asn1wr) Reset (out []byte, outLen uint32) {
    C.vscf_asn1wr_reset(this.cCtx, helperBytesToBytePtr(out)/*pa8*/, (C.size_t)(outLen)/*pa10*/)

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
func (this Asn1wr) Finish (doNotAdjust bool) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_finish(this.cCtx, (C.bool)(doNotAdjust)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Returns pointer to the inner buffer.
*/
func (this Asn1wr) Bytes () unsafe.Pointer {
    proxyResult := /*pr4*/C.vscf_asn1wr_bytes(this.cCtx)

    return unsafe.Pointer(proxyResult) /* r3 */
}

/*
* Returns total inner buffer length.
*/
func (this Asn1wr) Len () uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_len(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Returns how many bytes were already written to the ASN.1 structure.
*/
func (this Asn1wr) WrittenLen () uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_written_len(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Returns how many bytes are available for writing.
*/
func (this Asn1wr) UnwrittenLen () uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_unwritten_len(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Return true if status is not "success".
*/
func (this Asn1wr) HasError () bool {
    proxyResult := /*pr4*/C.vscf_asn1wr_has_error(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Return error code.
*/
func (this Asn1wr) Status () error {
    proxyResult := /*pr4*/C.vscf_asn1wr_status(this.cCtx)

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
func (this Asn1wr) Reserve (len uint32) unsafe.Pointer {
    proxyResult := /*pr4*/C.vscf_asn1wr_reserve(this.cCtx, (C.size_t)(len)/*pa10*/)

    return unsafe.Pointer(proxyResult) /* r3 */
}

/*
* Write ASN.1 tag.
* Return count of written bytes.
*/
func (this Asn1wr) WriteTag (tag int32) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_tag(this.cCtx, (C.int32_t)(tag)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write context-specific ASN.1 tag.
* Return count of written bytes.
*/
func (this Asn1wr) WriteContextTag (tag int32, len uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_context_tag(this.cCtx, (C.int32_t)(tag)/*pa10*/, (C.size_t)(len)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write length of the following data.
* Return count of written bytes.
*/
func (this Asn1wr) WriteLen (len uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_len(this.cCtx, (C.size_t)(len)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (this Asn1wr) WriteInt (value int32) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_int(this.cCtx, (C.int32_t)(value)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (this Asn1wr) WriteInt8 (value int8) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_int8(this.cCtx, (C.int8_t)(value)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (this Asn1wr) WriteInt16 (value int16) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_int16(this.cCtx, (C.int16_t)(value)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (this Asn1wr) WriteInt32 (value int32) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_int32(this.cCtx, (C.int32_t)(value)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (this Asn1wr) WriteInt64 (value int64) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_int64(this.cCtx, (C.int64_t)(value)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (this Asn1wr) WriteUint (value uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_uint(this.cCtx, (C.uint)(value)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (this Asn1wr) WriteUint8 (value uint8) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_uint8(this.cCtx, (C.uchar)(value)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (this Asn1wr) WriteUint16 (value uint16) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_uint16(this.cCtx, (C.ushort)(value)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (this Asn1wr) WriteUint32 (value uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_uint32(this.cCtx, (C.uint)(value)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (this Asn1wr) WriteUint64 (value uint64) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_uint64(this.cCtx, (C.ulong)(value)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: BOOLEAN.
* Return count of written bytes.
*/
func (this Asn1wr) WriteBool (value bool) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_bool(this.cCtx, (C.bool)(value)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: NULL.
*/
func (this Asn1wr) WriteNull () uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_null(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: OCTET STRING.
* Return count of written bytes.
*/
func (this Asn1wr) WriteOctetStr (value []byte) uint32 {
    valueData := C.vsc_data((*C.uint8_t)(&value[0]), C.size_t(len(value)))

    proxyResult := /*pr4*/C.vscf_asn1wr_write_octet_str(this.cCtx, valueData)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: BIT STRING with all zero unused bits.
*
* Return count of written bytes.
*/
func (this Asn1wr) WriteOctetStrAsBitstring (value []byte) uint32 {
    valueData := C.vsc_data((*C.uint8_t)(&value[0]), C.size_t(len(value)))

    proxyResult := /*pr4*/C.vscf_asn1wr_write_octet_str_as_bitstring(this.cCtx, valueData)

    return uint32(proxyResult) /* r9 */
}

/*
* Write raw data directly to the ASN.1 structure.
* Return count of written bytes.
* Note, use this method carefully.
*/
func (this Asn1wr) WriteData (data []byte) uint32 {
    dataData := C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))

    proxyResult := /*pr4*/C.vscf_asn1wr_write_data(this.cCtx, dataData)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: UTF8String.
* Return count of written bytes.
*/
func (this Asn1wr) WriteUtf8Str (value []byte) uint32 {
    valueData := C.vsc_data((*C.uint8_t)(&value[0]), C.size_t(len(value)))

    proxyResult := /*pr4*/C.vscf_asn1wr_write_utf8_str(this.cCtx, valueData)

    return uint32(proxyResult) /* r9 */
}

/*
* Write ASN.1 type: OID.
* Return count of written bytes.
*/
func (this Asn1wr) WriteOid (value []byte) uint32 {
    valueData := C.vsc_data((*C.uint8_t)(&value[0]), C.size_t(len(value)))

    proxyResult := /*pr4*/C.vscf_asn1wr_write_oid(this.cCtx, valueData)

    return uint32(proxyResult) /* r9 */
}

/*
* Mark previously written data of given length as ASN.1 type: SEQUENCE.
* Return count of written bytes.
*/
func (this Asn1wr) WriteSequence (len uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_sequence(this.cCtx, (C.size_t)(len)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Mark previously written data of given length as ASN.1 type: SET.
* Return count of written bytes.
*/
func (this Asn1wr) WriteSet (len uint32) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1wr_write_set(this.cCtx, (C.size_t)(len)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}
