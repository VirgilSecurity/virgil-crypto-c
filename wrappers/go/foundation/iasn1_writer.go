package foundation

import "C"
import unsafe "unsafe"

/*
* Provides interface to the ASN.1 writer.
* Note, elements are written starting from the buffer ending.
* Note, that all "write" methods move writing position backward.
*/
type IAsn1Writer interface {

    context

    /*
    * Reset all internal states and prepare to new ASN.1 writing operations.
    */
    Reset (out []byte, outLen uint32)

    /*
    * Finalize writing and forbid further operations.
    *
    * Note, that ASN.1 structure is always written to the buffer end, and
    * if argument "do not adjust" is false, then data is moved to the
    * beginning, otherwise - data is left at the buffer end.
    *
    * Returns length of the written bytes.
    */
    Finish (doNotAdjust bool) uint32

    /*
    * Returns pointer to the inner buffer.
    */
    Bytes () unsafe.Pointer

    /*
    * Returns total inner buffer length.
    */
    Len () uint32

    /*
    * Returns how many bytes were already written to the ASN.1 structure.
    */
    WrittenLen () uint32

    /*
    * Returns how many bytes are available for writing.
    */
    UnwrittenLen () uint32

    /*
    * Return true if status is not "success".
    */
    HasError () bool

    /*
    * Return error code.
    */
    Status () error

    /*
    * Move writing position backward for the given length.
    * Return current writing position.
    */
    Reserve (len uint32) unsafe.Pointer

    /*
    * Write ASN.1 tag.
    * Return count of written bytes.
    */
    WriteTag (tag int32) uint32

    /*
    * Write context-specific ASN.1 tag.
    * Return count of written bytes.
    */
    WriteContextTag (tag int32, len uint32) uint32

    /*
    * Write length of the following data.
    * Return count of written bytes.
    */
    WriteLen (len uint32) uint32

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    WriteInt (value int32) uint32

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    WriteInt8 (value int8) uint32

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    WriteInt16 (value int16) uint32

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    WriteInt32 (value int32) uint32

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    WriteInt64 (value int64) uint32

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    WriteUint (value uint32) uint32

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    WriteUint8 (value uint8) uint32

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    WriteUint16 (value uint16) uint32

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    WriteUint32 (value uint32) uint32

    /*
    * Write ASN.1 type: INTEGER.
    * Return count of written bytes.
    */
    WriteUint64 (value uint64) uint32

    /*
    * Write ASN.1 type: BOOLEAN.
    * Return count of written bytes.
    */
    WriteBool (value bool) uint32

    /*
    * Write ASN.1 type: NULL.
    */
    WriteNull () uint32

    /*
    * Write ASN.1 type: OCTET STRING.
    * Return count of written bytes.
    */
    WriteOctetStr (value []byte) uint32

    /*
    * Write ASN.1 type: BIT STRING with all zero unused bits.
    *
    * Return count of written bytes.
    */
    WriteOctetStrAsBitstring (value []byte) uint32

    /*
    * Write raw data directly to the ASN.1 structure.
    * Return count of written bytes.
    * Note, use this method carefully.
    */
    WriteData (data []byte) uint32

    /*
    * Write ASN.1 type: UTF8String.
    * Return count of written bytes.
    */
    WriteUtf8Str (value []byte) uint32

    /*
    * Write ASN.1 type: OID.
    * Return count of written bytes.
    */
    WriteOid (value []byte) uint32

    /*
    * Mark previously written data of given length as ASN.1 type: SEQUENCE.
    * Return count of written bytes.
    */
    WriteSequence (len uint32) uint32

    /*
    * Mark previously written data of given length as ASN.1 type: SET.
    * Return count of written bytes.
    */
    WriteSet (len uint32) uint32

    /*
    * Release underlying C context.
    */
    Delete ()
}

