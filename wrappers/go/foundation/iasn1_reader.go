package foundation

import "C"

/*
* Provides interface to the ASN.1 reader.
* Note, that all "read" methods move reading position forward.
* Note, that all "get" do not change reading position.
*/
type IAsn1Reader interface {

    CContext

    /*
    * Reset all internal states and prepare to new ASN.1 reading operations.
    */
    Reset (data []byte)

    /*
    * Return length in bytes how many bytes are left for reading.
    */
    LeftLen () int32

    /*
    * Return true if status is not "success".
    */
    HasError () bool

    /*
    * Return error code.
    */
    Status ()

    /*
    * Get tag of the current ASN.1 element.
    */
    GetTag () int32

    /*
    * Get length of the current ASN.1 element.
    */
    GetLen () int32

    /*
    * Get length of the current ASN.1 element with tag and length itself.
    */
    GetDataLen () int32

    /*
    * Read ASN.1 type: TAG.
    * Return element length.
    */
    ReadTag (tag int32) int32

    /*
    * Read ASN.1 type: context-specific TAG.
    * Return element length.
    * Return 0 if current position do not points to the requested tag.
    */
    ReadContextTag (tag int32) int32

    /*
    * Read ASN.1 type: INTEGER.
    */
    ReadInt () int32

    /*
    * Read ASN.1 type: INTEGER.
    */
    ReadInt8 () int8

    /*
    * Read ASN.1 type: INTEGER.
    */
    ReadInt16 () int16

    /*
    * Read ASN.1 type: INTEGER.
    */
    ReadInt32 () int32

    /*
    * Read ASN.1 type: INTEGER.
    */
    ReadInt64 () int64

    /*
    * Read ASN.1 type: INTEGER.
    */
    ReadUint () uint32

    /*
    * Read ASN.1 type: INTEGER.
    */
    ReadUint8 () uint8

    /*
    * Read ASN.1 type: INTEGER.
    */
    ReadUint16 () uint16

    /*
    * Read ASN.1 type: INTEGER.
    */
    ReadUint32 () uint32

    /*
    * Read ASN.1 type: INTEGER.
    */
    ReadUint64 () uint64

    /*
    * Read ASN.1 type: BOOLEAN.
    */
    ReadBool () bool

    /*
    * Read ASN.1 type: NULL.
    */
    ReadNull ()

    /*
    * Read ASN.1 type: NULL, only if it exists.
    * Note, this method is safe to call even no more data is left for reading.
    */
    ReadNullOptional ()

    /*
    * Read ASN.1 type: OCTET STRING.
    */
    ReadOctetStr () []byte

    /*
    * Read ASN.1 type: BIT STRING.
    */
    ReadBitstringAsOctetStr () []byte

    /*
    * Read ASN.1 type: UTF8String.
    */
    ReadUtf8Str () []byte

    /*
    * Read ASN.1 type: OID.
    */
    ReadOid () []byte

    /*
    * Read raw data of given length.
    */
    ReadData (len int32) []byte

    /*
    * Read ASN.1 type: SEQUENCE.
    * Return element length.
    */
    ReadSequence () int32

    /*
    * Read ASN.1 type: SET.
    * Return element length.
    */
    ReadSet () int32
}

