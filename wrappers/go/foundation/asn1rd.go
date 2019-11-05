package foundation

// #cgo CFLAGS: -I${SRCDIR}/../binaries/include/
// #cgo LDFLAGS: -L${SRCDIR}/../binaries/lib -lmbedcrypto -led25519 -lprotobuf-nanopb -lvsc_common -lvsc_foundation -lvsc_foundation_pb
// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"


/*
* This is MbedTLS implementation of ASN.1 reader.
*/
type Asn1rd struct {
    IAsn1Reader
    cCtx *C.vscf_asn1rd_t /*ct10*/
}

/* Handle underlying C context. */
func (this Asn1rd) ctx () *C.vscf_impl_t {
    return (*C.vscf_impl_t)(this.cCtx)
}

func NewAsn1rd () *Asn1rd {
    ctx := C.vscf_asn1rd_new()
    return &Asn1rd {
        cCtx: ctx,
    }
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newAsn1rdWithCtx (ctx *C.vscf_asn1rd_t /*ct10*/) *Asn1rd {
    return &Asn1rd {
        cCtx: ctx,
    }
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newAsn1rdCopy (ctx *C.vscf_asn1rd_t /*ct10*/) *Asn1rd {
    return &Asn1rd {
        cCtx: C.vscf_asn1rd_shallow_copy(ctx),
    }
}

/// Release underlying C context.
func (this Asn1rd) clear () {
    C.vscf_asn1rd_delete(this.cCtx)
}

/*
* Reset all internal states and prepare to new ASN.1 reading operations.
*/
func (this Asn1rd) Reset (data []byte) {
    dataData := helperWrapData (data)

    C.vscf_asn1rd_reset(this.cCtx, dataData)

    return
}

/*
* Return length in bytes how many bytes are left for reading.
*/
func (this Asn1rd) LeftLen () uint32 {
    proxyResult := /*pr4*/C.vscf_asn1rd_left_len(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Return true if status is not "success".
*/
func (this Asn1rd) HasError () bool {
    proxyResult := /*pr4*/C.vscf_asn1rd_has_error(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Return error code.
*/
func (this Asn1rd) Status () error {
    proxyResult := /*pr4*/C.vscf_asn1rd_status(this.cCtx)

    err := FoundationErrorHandleStatus(proxyResult)
    if err != nil {
        return err
    }

    return nil
}

/*
* Get tag of the current ASN.1 element.
*/
func (this Asn1rd) GetTag () int32 {
    proxyResult := /*pr4*/C.vscf_asn1rd_get_tag(this.cCtx)

    return int32(proxyResult) /* r9 */
}

/*
* Get length of the current ASN.1 element.
*/
func (this Asn1rd) GetLen () uint32 {
    proxyResult := /*pr4*/C.vscf_asn1rd_get_len(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Get length of the current ASN.1 element with tag and length itself.
*/
func (this Asn1rd) GetDataLen () uint32 {
    proxyResult := /*pr4*/C.vscf_asn1rd_get_data_len(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: TAG.
* Return element length.
*/
func (this Asn1rd) ReadTag (tag int32) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_tag(this.cCtx, (C.int32_t)(tag)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: context-specific TAG.
* Return element length.
* Return 0 if current position do not points to the requested tag.
*/
func (this Asn1rd) ReadContextTag (tag int32) uint32 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_context_tag(this.cCtx, (C.int32_t)(tag)/*pa10*/)

    return uint32(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: INTEGER.
*/
func (this Asn1rd) ReadInt () int32 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_int(this.cCtx)

    return int32(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: INTEGER.
*/
func (this Asn1rd) ReadInt8 () int8 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_int8(this.cCtx)

    return int8(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: INTEGER.
*/
func (this Asn1rd) ReadInt16 () int16 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_int16(this.cCtx)

    return int16(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: INTEGER.
*/
func (this Asn1rd) ReadInt32 () int32 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_int32(this.cCtx)

    return int32(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: INTEGER.
*/
func (this Asn1rd) ReadInt64 () int64 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_int64(this.cCtx)

    return int64(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: INTEGER.
*/
func (this Asn1rd) ReadUint () uint32 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_uint(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: INTEGER.
*/
func (this Asn1rd) ReadUint8 () uint8 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_uint8(this.cCtx)

    return uint8(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: INTEGER.
*/
func (this Asn1rd) ReadUint16 () uint16 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_uint16(this.cCtx)

    return uint16(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: INTEGER.
*/
func (this Asn1rd) ReadUint32 () uint32 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_uint32(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: INTEGER.
*/
func (this Asn1rd) ReadUint64 () uint64 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_uint64(this.cCtx)

    return uint64(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: BOOLEAN.
*/
func (this Asn1rd) ReadBool () bool {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_bool(this.cCtx)

    return bool(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: NULL.
*/
func (this Asn1rd) ReadNull () {
    C.vscf_asn1rd_read_null(this.cCtx)

    return
}

/*
* Read ASN.1 type: NULL, only if it exists.
* Note, this method is safe to call even no more data is left for reading.
*/
func (this Asn1rd) ReadNullOptional () {
    C.vscf_asn1rd_read_null_optional(this.cCtx)

    return
}

/*
* Read ASN.1 type: OCTET STRING.
*/
func (this Asn1rd) ReadOctetStr () []byte {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_octet_str(this.cCtx)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Read ASN.1 type: BIT STRING.
*/
func (this Asn1rd) ReadBitstringAsOctetStr () []byte {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_bitstring_as_octet_str(this.cCtx)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Read ASN.1 type: UTF8String.
*/
func (this Asn1rd) ReadUtf8Str () []byte {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_utf8_str(this.cCtx)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Read ASN.1 type: OID.
*/
func (this Asn1rd) ReadOid () []byte {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_oid(this.cCtx)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Read raw data of given length.
*/
func (this Asn1rd) ReadData (len uint32) []byte {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_data(this.cCtx, (C.size_t)(len)/*pa10*/)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Read ASN.1 type: SEQUENCE.
* Return element length.
*/
func (this Asn1rd) ReadSequence () uint32 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_sequence(this.cCtx)

    return uint32(proxyResult) /* r9 */
}

/*
* Read ASN.1 type: SET.
* Return element length.
*/
func (this Asn1rd) ReadSet () uint32 {
    proxyResult := /*pr4*/C.vscf_asn1rd_read_set(this.cCtx)

    return uint32(proxyResult) /* r9 */
}
