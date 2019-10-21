package foundation

// #cgo CFLAGS: -I${SRCDIR}/../../../build/library/foundation/include/virgil/crypto/foundation
// #cgo CFLAGS: -I${SRCDIR}/../../../library/foundation/include/virgil/crypto/foundation
// #cgo LDFLAGS: -L${SRCDIR}/../../java/binaries/linux/lib -lvscf_foundation_java
// #include <vscf_foundation_public.h>
import "C"
import . "virgil/common"

/*
* Implementation of the Base64 algorithm RFC 1421 and RFC 2045.
*/
type Base64 struct {
}

/*
* Calculate length in bytes required to hold an encoded base64 string.
*/
func Base64EncodedLen (dataLen int32) int32 {
    proxyResult := C.vscf_base64_encoded_len(dataLen)

    return proxyResult //r9
}

/*
* Encode given data to the base64 format.
* Note, written buffer is NOT null-terminated.
*/
func Base64Encode (data []byte) []byte {
    strCount := Base64EncodedLen(int32(len(data))) /* lg1 */
    strBuf := NewBuffer(strCount)
    defer strBuf.Clear()


    C.vscf_base64_encode(WrapData(data), strBuf)

    return strBuf.GetData() /* r7 */
}

/*
* Calculate length in bytes required to hold a decoded base64 string.
*/
func Base64DecodedLen (strLen int32) int32 {
    proxyResult := C.vscf_base64_decoded_len(strLen)

    return proxyResult //r9
}

/*
* Decode given data from the base64 format.
*/
func Base64Decode (str []byte) []byte {
    dataCount := Base64DecodedLen(int32(len(str))) /* lg1 */
    dataBuf := NewBuffer(dataCount)
    defer dataBuf.Clear()


    proxyResult := C.vscf_base64_decode(WrapData(str), dataBuf)

    FoundationErrorHandleStatus(proxyResult)

    return dataBuf.GetData() /* r7 */
}
