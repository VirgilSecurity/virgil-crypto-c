package foundation

import "C"

/*
* ASN.1 constants.
*/
type Asn1Tag int
const (
    Asn1TagBoolean Asn1Tag = 0x01
    Asn1TagInteger Asn1Tag = 0x02
    Asn1TagBitString Asn1Tag = 0x03
    Asn1TagOctetString Asn1Tag = 0x04
    Asn1TagNull Asn1Tag = 0x05
    Asn1TagOid Asn1Tag = 0x06
    Asn1TagUtf8String Asn1Tag = 0x0C
    Asn1TagSequence Asn1Tag = 0x10
    Asn1TagSet Asn1Tag = 0x11
    Asn1TagPrintableString Asn1Tag = 0x13
    Asn1TagT61String Asn1Tag = 0x14
    Asn1TagIa5String Asn1Tag = 0x16
    Asn1TagUtcTime Asn1Tag = 0x17
    Asn1TagGeneralizedTime Asn1Tag = 0x18
    Asn1TagUniversalString Asn1Tag = 0x1C
    Asn1TagBmpString Asn1Tag = 0x1E
    Asn1TagPrimitive Asn1Tag = 0x00
    Asn1TagConstructed Asn1Tag = 0x20
    Asn1TagContextSpecific Asn1Tag = 0x80
)
