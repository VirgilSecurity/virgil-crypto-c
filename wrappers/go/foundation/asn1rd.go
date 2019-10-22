package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_common
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lvsc_foundation
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* This is MbedTLS implementation of ASN.1 reader.
*/
type Asn1rd struct {
    IAsn1Reader
    ctx *C.vscf_impl_t
}

/* Handle underlying C context. */
func (this Asn1rd) Ctx () *C.vscf_impl_t {
    return this.ctx
}

func NewAsn1rd () *Asn1rd {
    ctx := C.vscf_asn1rd_new()
    return &Asn1rd {
        ctx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewAsn1rdWithCtx (ctx *C.vscf_impl_t) *Asn1rd {
    return &Asn1rd {
        ctx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func NewAsn1rdCopy (ctx *C.vscf_impl_t) *Asn1rd {
    return &Asn1rd {
        ctx: C.vscf_asn1rd_shallow_copy(ctx),
    }
}

/*
* Reset all internal states and prepare to new ASN.1 reading operations.
*/
func (this Asn1rd) Reset (data []byte) {
    C.vscf_asn1rd_reset(this.ctx, WrapData(data))
}

/*
* Return length in bytes how many bytes are left for reading.
*/
func (this Asn1rd) LeftLen () int32 {
    proxyResult := C.vscf_asn1rd_left_len(this.ctx)

    return proxyResult //r9
}

/*
* Return true if status is not "success".
*/
func (this Asn1rd) HasError () bool {
    proxyResult := C.vscf_asn1rd_has_error(this.ctx)

    return proxyResult //r9
}

/*
* Return error code.
*/
func (this Asn1rd) Status () {
    proxyResult := C.vscf_asn1rd_status(this.ctx)

    FoundationErrorHandleStatus(proxyResult)
}

/*
* Get tag of the current ASN.1 element.
*/
func (this Asn1rd) GetTag () int32 {
    proxyResult := C.vscf_asn1rd_get_tag(this.ctx)

    return proxyResult //r9
}

/*
* Get length of the current ASN.1 element.
*/
func (this Asn1rd) GetLen () int32 {
    proxyResult := C.vscf_asn1rd_get_len(this.ctx)

    return proxyResult //r9
}

/*
* Get length of the current ASN.1 element with tag and length itself.
*/
func (this Asn1rd) GetDataLen () int32 {
    proxyResult := C.vscf_asn1rd_get_data_len(this.ctx)

    return proxyResult //r9
}

/*
* Read ASN.1 type: TAG.
* Return element length.
*/
func (this Asn1rd) ReadTag (tag int32) int32 {
    proxyResult := C.vscf_asn1rd_read_tag(this.ctx, tag)

    return proxyResult //r9
}

/*
* Read ASN.1 type: context-specific TAG.
* Return element length.
* Return 0 if current position do not points to the requested tag.
*/
func (this Asn1rd) ReadContextTag (tag int32) int32 {
    proxyResult := C.vscf_asn1rd_read_context_tag(this.ctx, tag)

    return proxyResult //r9
}

/*
* Read ASN.1 type: INTEGER.
*/
func (this Asn1rd) ReadInt () int32 {
    proxyResult := C.vscf_asn1rd_read_int(this.ctx)

    return proxyResult //r9
}

/*
* Read ASN.1 type: INTEGER.
*/
func (this Asn1rd) ReadInt8 () int8 {
    proxyResult := C.vscf_asn1rd_read_int8(this.ctx)

    return proxyResult //r9
}

/*
* Read ASN.1 type: INTEGER.
*/
func (this Asn1rd) ReadInt16 () int16 {
    proxyResult := C.vscf_asn1rd_read_int16(this.ctx)

    return proxyResult //r9
}

/*
* Read ASN.1 type: INTEGER.
*/
func (this Asn1rd) ReadInt32 () int32 {
    proxyResult := C.vscf_asn1rd_read_int32(this.ctx)

    return proxyResult //r9
}

/*
* Read ASN.1 type: INTEGER.
*/
func (this Asn1rd) ReadInt64 () int64 {
    proxyResult := C.vscf_asn1rd_read_int64(this.ctx)

    return proxyResult //r9
}

/*
* Read ASN.1 type: INTEGER.
*/
func (this Asn1rd) ReadUint () uint32 {
    proxyResult := C.vscf_asn1rd_read_uint(this.ctx)

    return proxyResult //r9
}

/*
* Read ASN.1 type: INTEGER.
*/
func (this Asn1rd) ReadUint8 () uint8 {
    proxyResult := C.vscf_asn1rd_read_uint8(this.ctx)

    return proxyResult //r9
}

/*
* Read ASN.1 type: INTEGER.
*/
func (this Asn1rd) ReadUint16 () uint16 {
    proxyResult := C.vscf_asn1rd_read_uint16(this.ctx)

    return proxyResult //r9
}

/*
* Read ASN.1 type: INTEGER.
*/
func (this Asn1rd) ReadUint32 () uint32 {
    proxyResult := C.vscf_asn1rd_read_uint32(this.ctx)

    return proxyResult //r9
}

/*
* Read ASN.1 type: INTEGER.
*/
func (this Asn1rd) ReadUint64 () uint64 {
    proxyResult := C.vscf_asn1rd_read_uint64(this.ctx)

    return proxyResult //r9
}

/*
* Read ASN.1 type: BOOLEAN.
*/
func (this Asn1rd) ReadBool () bool {
    proxyResult := C.vscf_asn1rd_read_bool(this.ctx)

    return proxyResult //r9
}

/*
* Read ASN.1 type: NULL.
*/
func (this Asn1rd) ReadNull () {
    C.vscf_asn1rd_read_null(this.ctx)
}

/*
* Read ASN.1 type: NULL, only if it exists.
* Note, this method is safe to call even no more data is left for reading.
*/
func (this Asn1rd) ReadNullOptional () {
    C.vscf_asn1rd_read_null_optional(this.ctx)
}

/*
* Read ASN.1 type: OCTET STRING.
*/
func (this Asn1rd) ReadOctetStr () []byte {
    proxyResult := C.vscf_asn1rd_read_octet_str(this.ctx)

    return ExtractData(proxyResult) /* r1 */
}

/*
* Read ASN.1 type: BIT STRING.
*/
func (this Asn1rd) ReadBitstringAsOctetStr () []byte {
    proxyResult := C.vscf_asn1rd_read_bitstring_as_octet_str(this.ctx)

    return ExtractData(proxyResult) /* r1 */
}

/*
* Read ASN.1 type: UTF8String.
*/
func (this Asn1rd) ReadUtf8Str () []byte {
    proxyResult := C.vscf_asn1rd_read_utf8_str(this.ctx)

    return ExtractData(proxyResult) /* r1 */
}

/*
* Read ASN.1 type: OID.
*/
func (this Asn1rd) ReadOid () []byte {
    proxyResult := C.vscf_asn1rd_read_oid(this.ctx)

    return ExtractData(proxyResult) /* r1 */
}

/*
* Read raw data of given length.
*/
func (this Asn1rd) ReadData (len int32) []byte {
    proxyResult := C.vscf_asn1rd_read_data(this.ctx, len)

    return ExtractData(proxyResult) /* r1 */
}

/*
* Read ASN.1 type: SEQUENCE.
* Return element length.
*/
func (this Asn1rd) ReadSequence () int32 {
    proxyResult := C.vscf_asn1rd_read_sequence(this.ctx)

    return proxyResult //r9
}

/*
* Read ASN.1 type: SET.
* Return element length.
*/
func (this Asn1rd) ReadSet () int32 {
    proxyResult := C.vscf_asn1rd_read_set(this.ctx)

    return proxyResult //r9
}
