package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* This is MbedTLS implementation of ASN.1 writer.
*/
type Asn1wr struct {
    IAsn1Writer
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this Asn1wr) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewAsn1wr () *Asn1wr {
    ctx := C.vscf_asn1wr_new()
    return &Asn1wr {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewAsn1wrWithCtx (ctx *C.vscf_impl_t) *Asn1wr {
    return &Asn1wr {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewAsn1wrCopy (ctx *C.vscf_impl_t) *Asn1wr {
    return &Asn1wr {
        ctx: C.vscf_asn1wr_shallow_copy(ctx),
    }
}

/*
* Reset all internal states and prepare to new ASN.1 writing operations.
*/
func (this Asn1wr) Reset (out []byte, outLen int32) {
    C.vscf_asn1wr_reset(this.ctx, out, outLen)
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
func (this Asn1wr) Finish (doNotAdjust bool) int32 {
    proxyResult := C.vscf_asn1wr_finish(this.ctx, doNotAdjust)

    return proxyResult //r9
}

/*
* Returns pointer to the inner buffer.
*/
func (this Asn1wr) Bytes () *byte {
    proxyResult := C.vscf_asn1wr_bytes(this.ctx)

    return proxyResult /* r3 */
}

/*
* Returns total inner buffer length.
*/
func (this Asn1wr) Len () int32 {
    proxyResult := C.vscf_asn1wr_len(this.ctx)

    return proxyResult //r9
}

/*
* Returns how many bytes were already written to the ASN.1 structure.
*/
func (this Asn1wr) WrittenLen () int32 {
    proxyResult := C.vscf_asn1wr_written_len(this.ctx)

    return proxyResult //r9
}

/*
* Returns how many bytes are available for writing.
*/
func (this Asn1wr) UnwrittenLen () int32 {
    proxyResult := C.vscf_asn1wr_unwritten_len(this.ctx)

    return proxyResult //r9
}

/*
* Return true if status is not "success".
*/
func (this Asn1wr) HasError () bool {
    proxyResult := C.vscf_asn1wr_has_error(this.ctx)

    return proxyResult //r9
}

/*
* Return error code.
*/
func (this Asn1wr) Status () {
    proxyResult := C.vscf_asn1wr_status(this.ctx)

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Move writing position backward for the given length.
* Return current writing position.
*/
func (this Asn1wr) Reserve (len int32) *byte {
    proxyResult := C.vscf_asn1wr_reserve(this.ctx, len)

    return proxyResult /* r3 */
}

/*
* Write ASN.1 tag.
* Return count of written bytes.
*/
func (this Asn1wr) WriteTag (tag int32) int32 {
    proxyResult := C.vscf_asn1wr_write_tag(this.ctx, tag)

    return proxyResult //r9
}

/*
* Write context-specific ASN.1 tag.
* Return count of written bytes.
*/
func (this Asn1wr) WriteContextTag (tag int32, len int32) int32 {
    proxyResult := C.vscf_asn1wr_write_context_tag(this.ctx, tag, len)

    return proxyResult //r9
}

/*
* Write length of the following data.
* Return count of written bytes.
*/
func (this Asn1wr) WriteLen (len int32) int32 {
    proxyResult := C.vscf_asn1wr_write_len(this.ctx, len)

    return proxyResult //r9
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (this Asn1wr) WriteInt (value int32) int32 {
    proxyResult := C.vscf_asn1wr_write_int(this.ctx, value)

    return proxyResult //r9
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (this Asn1wr) WriteInt8 (value int8) int32 {
    proxyResult := C.vscf_asn1wr_write_int8(this.ctx, value)

    return proxyResult //r9
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (this Asn1wr) WriteInt16 (value int16) int32 {
    proxyResult := C.vscf_asn1wr_write_int16(this.ctx, value)

    return proxyResult //r9
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (this Asn1wr) WriteInt32 (value int32) int32 {
    proxyResult := C.vscf_asn1wr_write_int32(this.ctx, value)

    return proxyResult //r9
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (this Asn1wr) WriteInt64 (value int64) int32 {
    proxyResult := C.vscf_asn1wr_write_int64(this.ctx, value)

    return proxyResult //r9
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (this Asn1wr) WriteUint (value uint32) int32 {
    proxyResult := C.vscf_asn1wr_write_uint(this.ctx, value)

    return proxyResult //r9
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (this Asn1wr) WriteUint8 (value uint8) int32 {
    proxyResult := C.vscf_asn1wr_write_uint8(this.ctx, value)

    return proxyResult //r9
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (this Asn1wr) WriteUint16 (value uint16) int32 {
    proxyResult := C.vscf_asn1wr_write_uint16(this.ctx, value)

    return proxyResult //r9
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (this Asn1wr) WriteUint32 (value uint32) int32 {
    proxyResult := C.vscf_asn1wr_write_uint32(this.ctx, value)

    return proxyResult //r9
}

/*
* Write ASN.1 type: INTEGER.
* Return count of written bytes.
*/
func (this Asn1wr) WriteUint64 (value uint64) int32 {
    proxyResult := C.vscf_asn1wr_write_uint64(this.ctx, value)

    return proxyResult //r9
}

/*
* Write ASN.1 type: BOOLEAN.
* Return count of written bytes.
*/
func (this Asn1wr) WriteBool (value bool) int32 {
    proxyResult := C.vscf_asn1wr_write_bool(this.ctx, value)

    return proxyResult //r9
}

/*
* Write ASN.1 type: NULL.
*/
func (this Asn1wr) WriteNull () int32 {
    proxyResult := C.vscf_asn1wr_write_null(this.ctx)

    return proxyResult //r9
}

/*
* Write ASN.1 type: OCTET STRING.
* Return count of written bytes.
*/
func (this Asn1wr) WriteOctetStr (value []byte) int32 {
    proxyResult := C.vscf_asn1wr_write_octet_str(this.ctx, WrapData(value))

    return proxyResult //r9
}

/*
* Write ASN.1 type: BIT STRING with all zero unused bits.
*
* Return count of written bytes.
*/
func (this Asn1wr) WriteOctetStrAsBitstring (value []byte) int32 {
    proxyResult := C.vscf_asn1wr_write_octet_str_as_bitstring(this.ctx, WrapData(value))

    return proxyResult //r9
}

/*
* Write raw data directly to the ASN.1 structure.
* Return count of written bytes.
* Note, use this method carefully.
*/
func (this Asn1wr) WriteData (data []byte) int32 {
    proxyResult := C.vscf_asn1wr_write_data(this.ctx, WrapData(data))

    return proxyResult //r9
}

/*
* Write ASN.1 type: UTF8String.
* Return count of written bytes.
*/
func (this Asn1wr) WriteUtf8Str (value []byte) int32 {
    proxyResult := C.vscf_asn1wr_write_utf8_str(this.ctx, WrapData(value))

    return proxyResult //r9
}

/*
* Write ASN.1 type: OID.
* Return count of written bytes.
*/
func (this Asn1wr) WriteOid (value []byte) int32 {
    proxyResult := C.vscf_asn1wr_write_oid(this.ctx, WrapData(value))

    return proxyResult //r9
}

/*
* Mark previously written data of given length as ASN.1 type: SEQUENCE.
* Return count of written bytes.
*/
func (this Asn1wr) WriteSequence (len int32) int32 {
    proxyResult := C.vscf_asn1wr_write_sequence(this.ctx, len)

    return proxyResult //r9
}

/*
* Mark previously written data of given length as ASN.1 type: SET.
* Return count of written bytes.
*/
func (this Asn1wr) WriteSet (len int32) int32 {
    proxyResult := C.vscf_asn1wr_write_set(this.ctx, len)

    return proxyResult //r9
}
